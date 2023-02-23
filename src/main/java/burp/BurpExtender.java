package burp;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.common.helper.QpsLimiter;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.hae.HaE;
import burp.vaycore.onescan.OneScan;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.Constants;
import burp.vaycore.onescan.common.OnTabEventListener;
import burp.vaycore.onescan.ui.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.payloadlist.PayloadRule;
import burp.vaycore.onescan.ui.tab.ConfigPanel;
import burp.vaycore.onescan.ui.tab.DataBoardTab;
import burp.vaycore.onescan.ui.tab.config.OtherTab;
import burp.vaycore.onescan.ui.widget.TaskTable;
import org.json.HTTP;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener {

    private IBurpExtenderCallbacks mCallbacks;
    private OneScan mOneScan;
    private DataBoardTab mDataBoardTab;
    private ConfigPanel mConfigTab;
    private IMessageEditor mRequestTextEditor;
    private IMessageEditor mResponseTextEditor;
    private ExecutorService mThreadPool;
    private IHttpRequestResponse mCurrentReqResp;
    private static final Vector<String> sRepeatFilter = new Vector<>();
    private QpsLimiter mQpsLimit;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        initData(callbacks);
        initView();
        initEvent();
        Logger.debug("register Extender ok! Log: " + Constants.DEBUG);
        // 加载HaE插件
        HaE.loadPlugin(Config.getFilePath(Config.KEY_HAE_PLUGIN_PATH));
    }

    private void initData(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
        this.mThreadPool = Executors.newFixedThreadPool(50);
        this.mCallbacks.setExtensionName(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
        // 初始化日志打印
        Logger.init(Constants.DEBUG, mCallbacks.getStdout(), mCallbacks.getStderr());
        // 初始化默认配置
        Config.init();
        // 初始化域名辅助类
        DomainHelper.init("public_suffix_list.json");
        // 初始化HaE插件
        HaE.init(this);
        // 初始化QPS限制器
        initQpsLimiter();
    }

    private void initQpsLimiter() {
        // 检测范围，如果不符合条件，不创建限制器
        int limit = StringUtils.parseInt(Config.get(Config.KEY_QPS_LIMIT));
        if (limit > 0 && limit <= 9999) {
            this.mQpsLimit = new QpsLimiter(limit);
        }
    }

    private void initView() {
        mOneScan = new OneScan();
        mDataBoardTab = mOneScan.getDataBoardTab();
        mConfigTab = mOneScan.getConfigPanel();
        mCallbacks.addSuiteTab(this);
        // 创建请求和响应控件
        mRequestTextEditor = mCallbacks.createMessageEditor(this, false);
        mResponseTextEditor = mCallbacks.createMessageEditor(this, false);
        mDataBoardTab.init(mRequestTextEditor.getComponent(), mResponseTextEditor.getComponent());
        mDataBoardTab.getTaskTable().setOnTaskTableEventListener(this);
        // 注册事件
        mConfigTab.getOtherTab().setOnTabEventListener(this);
    }

    private void initEvent() {
        // 监听代理的包
        mCallbacks.registerProxyListener(this);
        // 注册菜单
        mCallbacks.registerContextMenuFactory((invocation) -> {
            ArrayList<JMenuItem> items = new ArrayList<>();
            // 扫描选定目标
            JMenuItem sendToOneScanItem = new JMenuItem("Send to OneScan");
            sendToOneScanItem.addActionListener((event) -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                for (IHttpRequestResponse httpReqResp : messages) {
                    doScan(httpReqResp);
                }
            });
            items.add(sendToOneScanItem);
            return items;
        });
    }

    @Override
    public String getTabCaption() {
        return Constants.PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mOneScan;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return mCallbacks;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // 检测开关状态
        if (!mDataBoardTab.hasListenProxyMessage()) {
            return;
        }
        // 当请求和响应都有的时候，才进行下一步操作
        if (messageIsRequest) return;
        IHttpRequestResponse httpReqResp = message.getMessageInfo();
        // 扫描任务
        doScan(httpReqResp);
    }

    private void doScan(IHttpRequestResponse httpReqResp) {
        String host = httpReqResp.getHttpService().getHost();
        // 先检测白名单
        if (hostWhitelistFilter(host)) {
            return;
        }
        // 再检测黑名单
        if (hostBlacklistFilter(host)) {
            return;
        }
        IExtensionHelpers helpers = mCallbacks.getHelpers();
        IRequestInfo request = helpers.analyzeRequest(httpReqResp);
        // 生成任务
        URL url = request.getUrl();
        Logger.debug("doScan receive: %s%s", getHostByUrl(url), url.getPath());
        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        // 收集一下Web应用名的信息
        collectWebName(pathDict);
        // 收集响应包中的Json字段信息
        collectJsonField(httpReqResp);
        // 一级目录一级目录递减访问
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            String path = pathDict.get(i);
            // 拼接字典，发起请求
            ArrayList<String> list = getPayloadList();
            for (String dict : list) {
                if (dict.startsWith("/")) {
                    dict = dict.substring(1);
                }
                String uri = path + dict;
                doPreRequest(httpReqResp, uri);
            }
        }
        // 原始请求也需要经过 Payload Process 处理（需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url)) {
            doBurpRequest(httpReqResp, httpReqResp.getRequest());
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s" + url.getPath());
        }
    }

    private ArrayList<String> getPayloadList() {
        return Config.getList(Config.KEY_PAYLOAD_LIST);
    }

    private ArrayList<String> getWhitelist() {
        return Config.getList(Config.KEY_WHITE_LIST);
    }

    private ArrayList<String> getBlacklist() {
        return Config.getList(Config.KEY_BLACK_LIST);
    }

    private ArrayList<String> getHeaderList() {
        return Config.getList(Config.KEY_HEADER_LIST);
    }

    /**
     * Host过滤白名单
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostWhitelistFilter(String host) {
        ArrayList<String> list = getWhitelist();
        // 白名单为空，不启用白名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (host.contains(item)) {
                return false;
            }
        }
        Logger.debug("hostWhitelistFilter filter host: %s", host);
        return true;
    }

    /**
     * Host过滤黑名单
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostBlacklistFilter(String host) {
        ArrayList<String> list = getBlacklist();
        // 黑名单为空，不启用黑名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (host.contains(item)) {
                Logger.debug("hostBlacklistFilter filter host: %s （rule: %s）", host, item);
                return true;
            }
        }
        return false;
    }

    /**
     * 代理请求的后缀过滤
     *
     * @param url 请求 url 对象
     * @return true=拦截；false=不拦截
     */
    private boolean proxyExcludeSuffixFilter(URL url) {
        if (url == null || StringUtils.isEmpty(url.getPath()) || "/".equals(url.getPath())) {
            return false;
        }
        String suffix = Config.get(Config.KEY_EXCLUDE_SUFFIX);
        String path = url.getPath();
        if (StringUtils.isEmpty(suffix)) {
            return false;
        }
        if (!suffix.contains("|") && path.endsWith(suffix)) {
            return true;
        }
        String[] split = suffix.split("\\|");
        for (String item : split) {
            if (path.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }

    private ArrayList<String> getUrlPathDict(String urlPath) {
        ArrayList<String> result = new ArrayList<>();
        result.add("/");
        if (StringUtils.isEmpty(urlPath) || "/".equals(urlPath)) {
            return result;
        }
        // 结尾如果不是'/'符号，去掉访问的文件
        if (!urlPath.endsWith("/")) {
            urlPath = urlPath.substring(0, urlPath.lastIndexOf("/") + 1);
        }
        String[] splitDirname = urlPath.split("/");
        if (splitDirname.length == 0) {
            return result;
        }
        StringBuilder sb = new StringBuilder("/");
        for (String dirname : splitDirname) {
            if (StringUtils.isNotEmpty(dirname)) {
                sb.append(dirname).append("/");
                result.add(sb.toString());
            }
        }
        return result;
    }

    private void doPreRequest(IHttpRequestResponse httpReqResp, String urlPath) {
        Logger.debug("doPreRequest receive urlPath: " + urlPath);
        String request = buildRequestHeader(httpReqResp, urlPath);
        doBurpRequest(httpReqResp, request.getBytes());
    }

    /**
     * 使用Burp自带的请求
     */
    private void doBurpRequest(IHttpRequestResponse httpReqResp, byte[] request) {
        IHttpService service = httpReqResp.getHttpService();
        // 处理请求包
        byte[] requestBytes = handlePayloadProcess(service, request);
        // 请求头构建完成后，需要进行 Payload Processing 处理
        IRequestInfo requestInfo = mCallbacks.getHelpers().analyzeRequest(service, requestBytes);
        String url = getHostByIHttpService(service) + requestInfo.getUrl().getPath();
        Logger.debug("doBurpRequest build ok! url: " + url);
        if (sRepeatFilter.contains(url)) {
            Logger.debug("doBurpRequest intercept url: " + url);
            return;
        }
        // 添加去重
        sRepeatFilter.add(url);
        // 给每个任务创建线程
        mThreadPool.execute(() -> {
            // 限制QPS
            if (mQpsLimit != null) {
                mQpsLimit.limit();
            }
            Logger.debug("Do Send Request url: " + url);
            // 发起请求
            IHttpRequestResponse newReqResp = mCallbacks.makeHttpRequest(service, requestBytes);
            Logger.debug("Request result url: " + url);
            // HaE提取信息
            HaE.processHttpMessage(newReqResp);
            // 构建展示的数据包
            TaskData data = buildTaskData(newReqResp);
            mDataBoardTab.getTaskTable().addTaskData(data);
            // 收集任务响应包中返回的Json字段信息
            collectJsonField(newReqResp);
        });
    }

    /**
     * 构建请求头
     */
    private String buildRequestHeader(IHttpRequestResponse httpReqResp, String urlPath) {
        IHttpService service = httpReqResp.getHttpService();
        ArrayList<String> headerList = getHeaderList();
        StringBuilder request = new StringBuilder();
        // 请求头构造
        request.append("GET ").append(urlPath).append(" HTTP/1.1").append(HTTP.CRLF);
        // 如果存在配置，直接加载配置的值，否则使用默认值
        if (headerList.size() > 0) {
            for (String headerItem : headerList) {
                int splitIndex = headerItem.indexOf(": ");
                if (splitIndex == -1) {
                    continue;
                }
                String headerKey = headerItem.substring(0, splitIndex);
                String headerValue = headerItem.substring(splitIndex + 2);
                request.append(headerKey).append(": ").append(headerValue).append(HTTP.CRLF);
            }
        } else {
            String referer = getHostByIHttpService(service) + "/";
            request.append("Host: {{host}}").append(HTTP.CRLF);
            request.append("User-Agent: ").append("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4495.0 Safari/537.36").append(HTTP.CRLF);
            request.append("Referer: ").append(referer).append(HTTP.CRLF);
            request.append("Accept: ").append("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").append(HTTP.CRLF);
            request.append("Accept-Language: ").append("zh-CN,zh;q=0.9,en;q=0.8").append(HTTP.CRLF);
            request.append("Accept-Encoding: ").append("gzip, deflate").append(HTTP.CRLF);
            request.append("Origin: ").append("https://www.baidu.com").append(HTTP.CRLF);
            request.append("Cache-Control: ").append("max-age=0").append(HTTP.CRLF);
        }
        request.append(HTTP.CRLF);
        // 请求头构建完成后，设置里面包含的变量
        return setupVariable(service, request.toString());
    }

    private String setupVariable(IHttpService service, String request) {
        String protocol = service.getProtocol();
        String host = service.getHost() + ":" + service.getPort();
        if (service.getPort() == 80 || service.getPort() == 443) {
            host = service.getHost();
        }
        String domain = service.getHost();
        String timestamp = String.valueOf(DateUtils.getTimestamp());
        String randomIP = IPUtils.randomIPv4();
        String randomUA = Utils.getRandomItem(Config.getList(Config.KEY_UA_LIST));
        String domainMain = DomainHelper.getDomain(domain);
        String domainName = DomainHelper.getDomainName(domain);
        // 替换变量
        request = request.replace("{{host}}", host);
        request = request.replace("{{domain}}", domain);
        request = request.replace("{{domain.main}}", domainMain);
        request = request.replace("{{domain.name}}", domainName);
        request = request.replace("{{protocol}}", protocol);
        request = request.replace("{{timestamp}}", timestamp);
        request = request.replace("{{random.ip}}", randomIP);
        request = request.replace("{{random.ua}}", randomUA);
        return request;
    }

    private byte[] handlePayloadProcess(IHttpService service, byte[] requestBytes) {
        if (requestBytes == null || requestBytes.length == 0) {
            return new byte[0];
        }
        ArrayList<PayloadItem> list = Config.getPayloadProcessList();
        IRequestInfo info = mCallbacks.getHelpers().analyzeRequest(service, requestBytes);
        int bodyOffset = info.getBodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = info.getUrl().getPath();
        String header = new String(requestBytes, 0, bodyOffset);
        String body;
        if (bodySize <= 0) {
            body = "";
        } else {
            body = new String(requestBytes, bodyOffset, bodySize);
        }
        String request = new String(requestBytes, 0, requestBytes.length);

        for (PayloadItem item : list) {
            // 只调用启用的规则
            PayloadRule rule = item.getRule();
            if (!item.isEnabled() || rule == null) {
                continue;
            }
            switch (item.getScope()) {
                case PayloadRule.SCOPE_URL:
                    String newUrl = rule.handleProcess(url);
                    request = request.replace(url, newUrl);
                    url = newUrl;
                    break;
                case PayloadRule.SCOPE_HEADER:
                    String newHeader = rule.handleProcess(header);
                    request = request.replace(header, newHeader);
                    header = newHeader;
                    break;
                case PayloadRule.SCOPE_BODY:
                    String newBody = rule.handleProcess(body);
                    request = header + newBody;
                    body = newBody;
                    break;
                case PayloadRule.SCOPE_REQUEST:
                    request = rule.handleProcess(request);
                    break;
            }
        }
        return request.getBytes();
    }

    /**
     * 构建Item数据
     *
     * @param httpReqResp Burp的请求响应对象
     * @return 列表Item数据
     */
    private TaskData buildTaskData(IHttpRequestResponse httpReqResp) {
        IExtensionHelpers helpers = mCallbacks.getHelpers();
        IRequestInfo request = helpers.analyzeRequest(httpReqResp);
        byte[] respBody = httpReqResp.getResponse();
        // 获取所需要的参数
        String method = request.getMethod();
        URL url = request.getUrl();
        String host = getHostByUrl(url);
        String reqUrl = getReqUrl(url);
        String title = HtmlUtils.findTitleByHtmlBody(respBody);
        String ip = findIpByHost(url.getHost());
        int status = -1;
        int length = -1;
        // 存在响应对象，获取状态和响应包大小
        if (respBody != null && respBody.length > 0) {
            IResponseInfo response = helpers.analyzeResponse(respBody);
            status = response.getStatusCode();
            // 处理响应 body 的长度
            length = respBody.length - response.getBodyOffset();
            if (length < 0) {
                length = 0;
            }
        }
        String comment = httpReqResp.getComment();

        // 构建表格对象
        TaskData data = new TaskData();
        data.setMethod(method);
        data.setHost(host);
        data.setUrl(reqUrl);
        data.setTitle(title);
        data.setIp(ip);
        data.setStatus(status);
        data.setLength(length);
        data.setComment(comment);
        data.setReqResp(httpReqResp);
        data.setHighlight(httpReqResp.getHighlight());
        return data;
    }

    private String getHostByIHttpService(IHttpService service) {
        String protocol = service.getProtocol();
        String host = service.getHost();
        int port = service.getPort();
        if (port == 80 || port == 443) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    private String getHostByUrl(URL url) {
        String protocol = url.getProtocol();
        String host = url.getHost();
        int port = url.getPort();
        if (port == 80 || port == 443) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    private String getReqUrl(URL url) {
        String path = url.getPath();
        String query = url.getQuery();
        if (StringUtils.isEmpty(query)) {
            return path;
        }
        return path + "?" + query;
    }

    private String findIpByHost(String host) {
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * 收集Web应用名
     */
    private void collectWebName(ArrayList<String> pathDict) {
        if (pathDict != null && pathDict.size() >= 2) {
            // 路径字典的格式是：/xxx/ ，所以需要处理一下
            String webName = pathDict.get(1).replace("/", "");
            // 去重
            String path = Config.getFilePath(Config.KEY_WEB_NAME_COLLECT_PATH);
            ArrayList<String> list = FileUtils.readFileToList(path);
            if (list == null || !list.contains(webName)) {
                FileUtils.writeFile(path, webName + "\n", true);
                Logger.debug("collectWebName webName: %s", webName);
            }
        }
    }

    /**
     * 收集json字段
     */
    private void collectJsonField(IHttpRequestResponse httpReqResp) {
        String host = httpReqResp.getHttpService().getHost();
        String domain = DomainHelper.getDomain(host);
        byte[] respBody = httpReqResp.getResponse();
        if (respBody == null || respBody.length == 0) {
            return;
        }
        // 保存路径
        String saveDir = Config.getFilePath(Config.KEY_JSON_FIELD_COLLECT_PATH, true);
        saveDir = saveDir + File.separator + domain;
        FileUtils.mkdirs(saveDir);
        String savePath = saveDir + File.separator + host + ".txt";

        // 解析响应
        IResponseInfo respInfo = mCallbacks.getHelpers().analyzeResponse(respBody);
        int bodyOffset = respInfo.getBodyOffset();
        int bodySize = respBody.length - bodyOffset;
        // 检测响应包是否没有body内容
        if (bodySize <= 0) {
            return;
        }
        String respJson = new String(respBody, bodyOffset, bodySize);
        // 尝试解析，解析成功再查询所有key的值
        if (hasJsonFormat(respJson)) {
            ArrayList<String> list = FileUtils.readFileToList(savePath);
            ArrayList<String> keys = JsonUtils.findAllKeysByJson(respJson);
            if (list == null) {
                list = new ArrayList<>();
            }
            StringBuilder sb = new StringBuilder();
            for (String key : keys) {
                if (!list.contains(key)) {
                    sb.append(key).append("\n");
                }
            }
            FileUtils.writeFile(savePath, sb.toString(), true);
            Logger.debug("collectJsonField host: %s keys: %s", domain, keys.toString());
        }
    }

    private boolean hasJsonFormat(String json) {
        try {
            new JSONObject(json);
            return true;
        } catch (Exception e) {
            try {
                new JSONArray(json);
                return true;
            } catch (Exception ex) {
                return false;
            }
        }
    }

    @Override
    public IHttpService getHttpService() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getHttpService();
        }
        return null;
    }

    @Override
    public byte[] getRequest() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getRequest();
        }
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        if (mCurrentReqResp != null) {
            return mCurrentReqResp.getResponse();
        }
        return new byte[0];
    }

    @Override
    public void onChangeSelection(TaskData data) {
        if (data != null) {
            mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        } else {
            mCurrentReqResp = null;
            // 清空记录时，同时也清空去重过滤列表
            sRepeatFilter.clear();
        }
        mRequestTextEditor.setMessage(getRequest(), true);
        mResponseTextEditor.setMessage(getResponse(), false);
    }

    @Override
    public void onSendToRepeater(ArrayList<TaskData> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (TaskData data : list) {
            if (data.getReqResp() == null) {
                continue;
            }
            byte[] reqBody = ((IHttpRequestResponse) data.getReqResp()).getRequest();
            String url = data.getHost() + data.getUrl();
            try {
                URL u = new URL(url);
                boolean useHttps = false;
                int port = u.getPort();
                if (port == -1) {
                    port = 80;
                }
                if ("https".equalsIgnoreCase(u.getProtocol())) {
                    useHttps = true;
                    port = 443;
                }
                mCallbacks.sendToRepeater(u.getHost(), port, useHttps, reqBody, null);
            } catch (Exception e) {
                Logger.debug(e.getMessage());
            }
        }
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        switch (action) {
            case OtherTab.EVENT_QPS_LIMIT:
                String limit = (String) params[0];
                mQpsLimit = new QpsLimiter(StringUtils.parseInt(limit));
                Logger.debug("Event: change qps limit: " + limit);
                break;
        }
    }
}
