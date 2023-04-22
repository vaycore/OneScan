package burp;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.common.helper.QpsLimiter;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.hae.HaE;
import burp.vaycore.onescan.OneScan;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.Constants;
import burp.vaycore.onescan.common.OnTabEventListener;
import burp.vaycore.onescan.info.OneScanInfoTab;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.tab.DataBoardTab;
import burp.vaycore.onescan.ui.tab.config.RequestTab;
import burp.vaycore.onescan.ui.widget.TaskTable;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener, IMessageEditorTabFactory {
    /**
     * 设置请求信息的同步锁
     */
    private static final String MESSAGE_LOCK = "MESSAGE-LOCK";
    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private OneScan mOneScan;
    private DataBoardTab mDataBoardTab;
    private IMessageEditor mRequestTextEditor;
    private IMessageEditor mResponseTextEditor;
    private ExecutorService mThreadPool;
    private ExecutorService mFpThreadPool;
    private IHttpRequestResponse mCurrentReqResp;
    private static final Vector<String> sRepeatFilter = new Vector<>();
    private QpsLimiter mQpsLimit;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        initData(callbacks);
        initView();
        initEvent();
        Logger.debug("register Extender ok! Log: %b", Constants.DEBUG);
        // 加载HaE插件
        HaE.loadPlugin(Config.getFilePath(Config.KEY_HAE_PLUGIN_PATH));
    }

    private void initData(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
        this.mHelpers = callbacks.getHelpers();
        this.mThreadPool = Executors.newFixedThreadPool(50);
        this.mFpThreadPool = Executors.newFixedThreadPool(10);
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
        // 注册 OneScan 信息辅助面板
        this.mCallbacks.registerMessageEditorTabFactory(this);
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
        // 注册事件
        mOneScan.getConfigPanel().setOnTabEventListener(this);
        mCallbacks.addSuiteTab(this);
        // 创建请求和响应控件
        mRequestTextEditor = mCallbacks.createMessageEditor(this, false);
        mResponseTextEditor = mCallbacks.createMessageEditor(this, false);
        mDataBoardTab.init(mRequestTextEditor.getComponent(), mResponseTextEditor.getComponent());
        mDataBoardTab.getTaskTable().setOnTaskTableEventListener(this);
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
                    doScan(httpReqResp, false);
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
        // 当请求和响应都有的时候，启用线程识别指纹，将识别结果缓存起来
        if (!messageIsRequest) {
            mFpThreadPool.execute(() -> FpManager.check(message.getMessageInfo().getResponse()));
        }
        // 检测开关状态
        if (!mDataBoardTab.hasListenProxyMessage()) {
            return;
        }
        // 当请求和响应都有的时候，才进行下一步操作
        if (messageIsRequest) return;
        IHttpRequestResponse httpReqResp = message.getMessageInfo();
        // 扫描任务
        doScan(httpReqResp, true);
    }

    private void doScan(IHttpRequestResponse httpReqResp, boolean fromProxy) {
        IRequestInfo request = mHelpers.analyzeRequest(httpReqResp);
        String host = httpReqResp.getHttpService().getHost();
        // 对来自代理的包进行检测，检测请求方法是否需要拦截
        if (fromProxy) {
            String method = request.getMethod();
            if (includeMethodFilter(method)) {
                // 拦截不匹配的请求方法
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
            // 检测Host是否在白名单、黑名单列表中
            if (hostWhitelistFilter(host) || hostBlacklistFilter(host)) {
                Logger.debug("doScan whitelist、blacklist filter host: %s", host);
                return;
            }
        }
        // 生成任务
        URL url = request.getUrl();
        Logger.debug("doScan receive: %s%s", getHostByUrl(url), url.getPath());
        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        // 收集一下Web应用名的信息
        collectWebName(pathDict);
        // 收集响应包中的Json字段信息
        collectJsonField(httpReqResp);
        // 检测是否禁用递归扫描
        if (!mDataBoardTab.hasDisableDirScan()) {
            // 一级目录一级目录递减访问
            for (int i = pathDict.size() - 1; i >= 0; i--) {
                String path = pathDict.get(i);
                // 拼接字典，发起请求
                List<String> list = WordlistManager.getPayload();
                for (String dict : list) {
                    if (dict.startsWith("/")) {
                        dict = dict.substring(1);
                    }
                    String urlPath = path + dict;
                    doPreRequest(httpReqResp, urlPath);
                }
            }
        }
        // 原始请求也需要经过 Payload Process 处理（需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url)) {
            doBurpRequest(httpReqResp, httpReqResp.getRequest());
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
    }

    /**
     * 过滤请求方法
     *
     * @param method 请求方法
     * @return true=拦截；false=不拦截
     */
    private boolean includeMethodFilter(String method) {
        String includeMethod = Config.get(Config.KEY_INCLUDE_METHOD);
        // 如果配置为空，不拦截任何请求方法
        if (StringUtils.isNotEmpty(includeMethod)) {
            String[] split = includeMethod.split("\\|");
            boolean hasFilter = true;
            for (String item : split) {
                if (method.equals(item)) {
                    hasFilter = false;
                    break;
                }
            }
            return hasFilter;
        }
        return false;
    }

    /**
     * Host过滤白名单
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostWhitelistFilter(String host) {
        List<String> list = WordlistManager.getWhiteHost();
        // 白名单为空，不启用白名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
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
        List<String> list = WordlistManager.getBlackHost();
        // 黑名单为空，不启用黑名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                Logger.debug("hostBlacklistFilter filter host: %s （rule: %s）", host, item);
                return true;
            }
        }
        return false;
    }

    /**
     * 检测 Host 是否匹配规则
     *
     * @param host Host
     * @param rule 规则
     * @return true=匹配；false=不匹配
     */
    private static boolean matchHost(String host, String rule) {
        if (StringUtils.isEmpty(host)) {
            return StringUtils.isEmpty(rule);
        }
        // 规则就是*号，直接返回true
        if (rule.equals("*")) {
            return true;
        }
        // 不包含*号，检测 Host 与规则是否相等
        if (!rule.contains("*")) {
            return host.equals(rule);
        }
        // 根据*号位置，进行匹配
        String ruleValue = rule.replace("*", "");
        if (rule.startsWith("*") && rule.endsWith("*")) {
            return host.contains(ruleValue);
        } else if (rule.startsWith("*")) {
            return host.endsWith(ruleValue);
        } else if (rule.endsWith("*")) {
            return host.startsWith(ruleValue);
        } else {
            String[] split = rule.split("\\*");
            return host.startsWith(split[0]) && host.endsWith(split[1]);
        }
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
        Logger.debug("doPreRequest receive urlPath: %s", urlPath);
        String request = buildRequestHeader(httpReqResp, urlPath);
        doBurpRequest(httpReqResp, request.getBytes());
    }

    /**
     * 使用Burp自带的请求
     */
    private void doBurpRequest(IHttpRequestResponse httpReqResp, byte[] request) {
        IHttpService service = httpReqResp.getHttpService();
        // 处理排除请求头
        request = handleExcludeHeader(httpReqResp, request);
        // 处理请求包
        byte[] requestBytes = handlePayloadProcess(service, request);
        // 请求头构建完成后，需要进行 Payload Processing 处理
        IRequestInfo requestInfo = mHelpers.analyzeRequest(service, requestBytes);
        String url = getHostByIHttpService(service) + requestInfo.getUrl().getPath();
        Logger.debug("doBurpRequest build ok! url: %s", url);
        if (sRepeatFilter.contains(url)) {
            Logger.debug("doBurpRequest intercept url: %s", url);
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
            Logger.debug("Do Send Request url: %s", url);
            // 发起请求
            IHttpRequestResponse newReqResp = mCallbacks.makeHttpRequest(service, requestBytes);
            Logger.debug("Request result url: %s", url);
            // HaE提取信息
            HaE.processHttpMessage(newReqResp);
            // 构建展示的数据包
            TaskData data = buildTaskData(newReqResp);
            mDataBoardTab.getTaskTable().addTaskData(data);
            // 收集任务响应包中返回的Json字段信息
            collectJsonField(newReqResp);
        });
    }

    private byte[] handleExcludeHeader(IHttpRequestResponse httpReqResp, byte[] request) {
        boolean state = mDataBoardTab.hasEnableExcludeHeader();
        List<String> excludeHeader = WordlistManager.getExcludeHeader();
        if (!state || excludeHeader.isEmpty()) {
            return request;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp.getHttpService(), request);
        List<String> headers = info.getHeaders();
        StringBuilder sb = new StringBuilder();
        // 把第一行排除
        sb.append(headers.get(0)).append("\r\n");
        for (int i = 1; i < headers.size(); i++) {
            String headerItem = headers.get(i);
            String headerKey = headerItem.split(": ")[0];
            if (!excludeHeader.contains(headerKey)) {
                sb.append(headerItem).append("\r\n");
            }
        }
        sb.append("\r\n");
        // 判断是否有body
        int bodySize = request.length - info.getBodyOffset();
        if (bodySize > 0) {
            sb.append(new String(request, info.getBodyOffset(), bodySize));
        }
        return sb.toString().getBytes();
    }

    /**
     * 构建请求头
     */
    private String buildRequestHeader(IHttpRequestResponse httpReqResp, String urlPath) {
        IHttpService service = httpReqResp.getHttpService();
        List<String> headerList = WordlistManager.getHeader();
        StringBuilder request = new StringBuilder();
        // 请求头构造
        request.append("GET ").append(urlPath).append(" HTTP/1.1").append("\r\n");
        // 如果存在配置并且未禁用替换请求头，直接加载配置的值，否则使用原请求包的请求头
        if (!mDataBoardTab.hasDisableHeaderReplace() && headerList.size() > 0) {
            for (String headerItem : headerList) {
                int splitIndex = headerItem.indexOf(": ");
                if (splitIndex == -1) {
                    continue;
                }
                String headerKey = headerItem.substring(0, splitIndex);
                String headerValue = headerItem.substring(splitIndex + 2);
                request.append(headerKey).append(": ").append(headerValue).append("\r\n");
            }
        } else {
            IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
            List<String> headers = info.getHeaders();
            for (int i = 1; i < headers.size(); i++) {
                request.append(headers.get(i)).append("\r\n");
            }
        }
        request.append("\r\n");
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
        String randomIP = IPUtils.randomIPv4ForLocal();
        String randomLocalIP = IPUtils.randomIPv4ForLocal();
        String randomUA = Utils.getRandomItem(WordlistManager.getUserAgent());
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
        request = request.replace("{{random.local-ip}}", randomLocalIP);
        request = request.replace("{{random.ua}}", randomUA);
        return request;
    }

    private byte[] handlePayloadProcess(IHttpService service, byte[] requestBytes) {
        if (requestBytes == null || requestBytes.length == 0) {
            return new byte[0];
        }
        ArrayList<PayloadItem> list = Config.getPayloadProcessList();
        IRequestInfo info = mHelpers.analyzeRequest(service, requestBytes);
        int bodyOffset = info.getBodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = info.getUrl().getPath();
        String header = new String(requestBytes, 0, bodyOffset);
        String body = bodySize <= 0 ? "" : new String(requestBytes, bodyOffset, bodySize);
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
                    // 截取请求头第一行，用于定位要处理的位置
                    String temp = header.substring(0, header.indexOf("\r\n"));
                    int start = temp.indexOf("/");
                    int end = temp.lastIndexOf(" ");
                    // 需要拿原数据包的URL检测是否存在'?'号，否则将导致多次拼接数据
                    if (info.getUrl().toString().contains("?")) {
                        end = temp.lastIndexOf("?");
                    }
                    // 分隔要插入数据的位置
                    String left = header.substring(0, start);
                    String right = header.substring(end);
                    // 拼接处理好的数据
                    header = left + newUrl + right;
                    request = header + body;
                    url = newUrl;
                    break;
                case PayloadRule.SCOPE_HEADER:
                    String newHeader = rule.handleProcess(header);
                    request = newHeader + body;
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
        IRequestInfo request = mHelpers.analyzeRequest(httpReqResp);
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
            IResponseInfo response = mHelpers.analyzeResponse(respBody);
            status = response.getStatusCode();
            // 处理响应 body 的长度
            length = respBody.length - response.getBodyOffset();
            if (length < 0) {
                length = 0;
            }
        }
        String comment = httpReqResp.getComment();
        // 检测指纹数据
        List<FpData> fpDataList = FpManager.check(httpReqResp.getResponse());
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
        data.setFingerprint(FpManager.listToNames(fpDataList));
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
        IResponseInfo respInfo = mHelpers.analyzeResponse(respBody);
        int bodyOffset = respInfo.getBodyOffset();
        int bodySize = respBody.length - bodyOffset;
        // 检测响应包是否没有body内容
        if (bodySize <= 0) {
            return;
        }
        String respJson = new String(respBody, bodyOffset, bodySize);
        // 尝试解析，解析成功再查询所有key的值
        if (JsonUtils.hasJson(respJson)) {
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
        // 如果数据太大，尝试调用线程设置请求信息
        int totalLength = getRequest().length + getResponse().length;
        if (totalLength >= 256000) {
            mRequestTextEditor.setMessage("Loading...".getBytes(), true);
            mResponseTextEditor.setMessage("Loading...".getBytes(), false);
            mThreadPool.execute(() -> {
                synchronized (MESSAGE_LOCK) {
                    refreshReqRespMessage();
                }
            });
        } else {
            refreshReqRespMessage();
        }
    }

    /**
     * 刷新请求响应信息
     */
    private void refreshReqRespMessage() {
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
                int port = u.getPort();
                boolean useHttps = "https".equalsIgnoreCase(u.getProtocol());
                if (port == -1) {
                    port = useHttps ? 443 : 80;
                }
                mCallbacks.sendToRepeater(u.getHost(), port, useHttps, reqBody, null);
            } catch (Exception e) {
                Logger.debug(e.getMessage());
            }
        }
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        if (RequestTab.EVENT_QPS_LIMIT.equals(action)) {
            String limit = (String) params[0];
            mQpsLimit = new QpsLimiter(StringUtils.parseInt(limit));
            Logger.debug("Event: change qps limit: %s", limit);
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean editable) {
        return new OneScanInfoTab(mCallbacks);
    }
}
