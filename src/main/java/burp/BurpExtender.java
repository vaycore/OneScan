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
import burp.vaycore.onescan.common.HttpReqRespAdapter;
import burp.vaycore.onescan.common.OnTabEventListener;
import burp.vaycore.onescan.info.OneScanInfoTab;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.tab.DataBoardTab;
import burp.vaycore.onescan.ui.tab.config.OtherTab;
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
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener, IMessageEditorTabFactory {

    /**
     * 任务线程数量
     */
    private static final int TASK_THREAD_COUNT = 50;

    /**
     * 指纹识别线程数量
     */
    private static final int FP_THREAD_COUNT = 10;

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
    private static final Vector<String> sWaitTasks = new Vector<>();
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
        this.mThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        this.mFpThreadPool = Executors.newFixedThreadPool(FP_THREAD_COUNT);
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
        mDataBoardTab.setOnTabEventListener(this);
        mOneScan.getConfigPanel().setOnTabEventListener(this);
        // 将页面添加到 BurpSuite
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
                    doScan(httpReqResp, "Send");
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
        // 当请求和响应都有的时候，才进行下一步操作
        if (messageIsRequest) {
            return;
        }
        // 开启线程识别指纹，将识别结果缓存起来
        mFpThreadPool.execute(() -> FpManager.check(message.getMessageInfo().getResponse()));
        // 检测开关状态
        if (!mDataBoardTab.hasListenProxyMessage()) {
            return;
        }
        IHttpRequestResponse httpReqResp = message.getMessageInfo();
        // 扫描任务
        doScan(httpReqResp, "Proxy");
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from) {
        IRequestInfo request = mHelpers.analyzeRequest(httpReqResp);
        String host = httpReqResp.getHttpService().getHost();
        // 对来自代理的包进行检测，检测请求方法是否需要拦截
        if (from.equals("Proxy")) {
            String method = request.getMethod();
            if (includeMethodFilter(method)) {
                // 拦截不匹配的请求方法
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
            // 检测 Host 是否在白名单、黑名单列表中
            if (hostWhitelistFilter(host) || hostBlacklistFilter(host)) {
                Logger.debug("doScan whitelist and blacklist filter host: %s", host);
                return;
            }
        }
        // 生成任务
        URL url = request.getUrl();
        // 原始请求也需要经过 Payload Process 处理（不过需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url)) {
            runScanTask(httpReqResp, null, from);
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
        // 检测是否禁用递归扫描
        if (!mDataBoardTab.hasDirScan()) {
            return;
        }
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
            List<String> list = WordlistManager.getPayload();
            for (String dict : list) {
                if (path.endsWith("/")) {
                    path = path.substring(0, path.length() - 1);
                }
                String urlPath = path + dict;
                runScanTask(httpReqResp, urlPath, "Scan");
            }
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
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        int scanLevel = StringUtils.parseInt(Config.get(Config.KEY_SCAN_LEVEL));
        ArrayList<String> result = new ArrayList<>();
        result.add("/");
        if (StringUtils.isEmpty(urlPath) || "/".equals(urlPath)) {
            return result;
        }
        // 限制方向从左往右，并且扫描层级为1
        if (Config.DIRECT_LEFT.equals(direct) && scanLevel <= 1) {
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
        // 限制方向从右往左，默认不扫描根目录
        if (Config.DIRECT_RIGHT.equals(direct) && scanLevel < splitDirname.length) {
            result.remove("/");
        }
        StringBuilder sb = new StringBuilder("/");
        for (String dirname : splitDirname) {
            if (StringUtils.isNotEmpty(dirname)) {
                sb.append(dirname).append("/");
                int level = StringUtils.countMatches(sb.toString(), "/");
                // 根据不同方向，限制目录层级
                if (Config.DIRECT_LEFT.equals(direct) && level > scanLevel) {
                    continue;
                } else if (Config.DIRECT_RIGHT.equals(direct)) {
                    level = splitDirname.length - level;
                    if (level >= scanLevel) {
                        continue;
                    }
                }
                result.add(sb.toString());
            }
        }

        return result;
    }

    /**
     * 运行扫描任务
     *
     * @param httpReqResp   请求响应实例
     * @param pathWithQuery 路径+query参数
     * @param from          请求来源
     */
    private void runScanTask(IHttpRequestResponse httpReqResp, String pathWithQuery, String from) {
        IHttpService service = httpReqResp.getHttpService();
        boolean mergePayloadProcessing = mDataBoardTab.hasMergePayloadProcessing();
        // 处理排除请求头
        byte[] request = handleHeader(httpReqResp, pathWithQuery, from);
        if (!mergePayloadProcessing) {
            doBurpRequest(service, request, from);
        }
        // 进行 Payload Processing 处理后，再次请求数据包
        byte[] requestBytes = handlePayloadProcess(service, request);
        doBurpRequest(service, requestBytes, from);
    }

    /**
     * 使用Burp自带的方式请求
     *
     * @param service     请求目标服务实例
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void doBurpRequest(IHttpService service, byte[] reqRawBytes, String from) {
        IRequestInfo requestInfo = mHelpers.analyzeRequest(service, reqRawBytes);
        String url = getHostByIHttpService(service) + requestInfo.getUrl().getPath();
        if (sRepeatFilter.contains(url)) {
            Logger.debug("doBurpRequest intercept url: %s", url);
            return;
        }
        Logger.debug("doBurpRequest build ok! url: %s", url);
        // 线程池关闭后，不接收任何任务
        if (mThreadPool.isShutdown()) {
            Logger.info("Thread pool is shutdown, intercept url: %s", url);
            return;
        }
        // 将 URL 添加到去重列表
        sRepeatFilter.addElement(url);
        sWaitTasks.addElement(url);
        // 给每个任务创建线程
        mThreadPool.execute(() -> {
            // 限制QPS
            if (mQpsLimit != null) {
                try {
                    mQpsLimit.limit();
                } catch (InterruptedException e) {
                    // 将等待的任务从过滤列表删除，并清空等待任务列表
                    if (!sWaitTasks.isEmpty()) {
                        sRepeatFilter.removeAll(sWaitTasks);
                        sWaitTasks.clear();
                    }
                    return;
                }
            }
            Logger.debug("Do Send Request url: %s", url);
            // 开始发送请求前，移除等待列表中的 URL 链接
            if (sWaitTasks.contains(url)) {
                sWaitTasks.removeElement(url);
            }
            // 发起请求
            IHttpRequestResponse newReqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);
            Logger.debug("Request result url: %s", url);
            // HaE提取信息
            HaE.processHttpMessage(newReqResp);
            // 构建展示的数据包
            TaskData data = buildTaskData(newReqResp);
            // 用于过滤代理数据包
            data.setFrom(from);
            mDataBoardTab.getTaskTable().addTaskData(data);
            // 收集任务响应包中返回的Json字段信息
            collectJsonField(newReqResp);
        });
    }

    /**
     * 处理请求头
     *
     * @param httpReqResp   Burp 的 HTTP 请求响应接口
     * @param pathWithQuery 请求路径，或者请求路径+Query（示例：/xxx、/xxx/index?a=xxx&b=xxx）
     * @param from          数据来源
     * @return 处理完成的数据包
     */
    private byte[] handleHeader(IHttpRequestResponse httpReqResp, String pathWithQuery, String from) {
        IHttpService service = httpReqResp.getHttpService();
        // 配置的请求头
        List<String> configHeader = getHeader();
        // 要排除的请求头KEY列表
        List<String> excludeHeader = getExcludeHeader();
        // 数据包自带的请求头
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        List<String> headers = info.getHeaders();
        // 构建请求头
        StringBuilder request = new StringBuilder();
        // 根据数据来源区分两种请求头
        if (from.equals("Scan")) {
            request.append("GET ").append(pathWithQuery).append(" HTTP/1.1").append("\r\n");
        } else {
            String reqLine = headers.get(0);
            int start = reqLine.lastIndexOf("HTTP/");
            reqLine = reqLine.substring(0, start) + "HTTP/1.1";
            request.append(reqLine).append("\r\n");
        }
        // 请求头的参数处理（顺带处理排除的请求头）
        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            String key = item.split(": ")[0];
            // 是否需要排除当前KEY（优先级最高）
            if (excludeHeader.contains(key)) {
                continue;
            }
            // 如果是扫描的请求，将 Content-Length 排除
            if (from.equals("Scan") && "Content-Length".equals(key)) {
                continue;
            }
            // 检测配置中是否存在当前请求头KEY
            List<String> matchList = configHeader.stream().filter(configHeaderItem -> {
                if (StringUtils.isNotEmpty(configHeaderItem) && configHeaderItem.contains(": ")) {
                    String configHeaderKey = configHeaderItem.split(": ")[0];
                    // 是否需要排除当前KEY
                    if (excludeHeader.contains(key)) {
                        return false;
                    }
                    return configHeaderKey.equals(key);
                }
                return false;
            }).collect(Collectors.toList());
            // 配置中存在匹配项，替换为配置中的数据
            if (matchList.size() > 0) {
                for (String matchItem : matchList) {
                    request.append(matchItem).append("\r\n");
                }
                // 将已经添加的数据从列表中移除
                configHeader.removeAll(matchList);
            } else {
                // 不存在匹配项，填充原数据
                request.append(item).append("\r\n");
            }
        }
        // 将配置里剩下的值全部填充到请求头中
        for (String item : configHeader) {
            String key = item.split(": ")[0];
            if (excludeHeader.contains(key)) {
                continue;
            }
            request.append(item).append("\r\n");
        }
        request.append("\r\n");
        // 如果当前数据来源不是 Scan，可能会包含 POST 请求，判断是否存在 body 数据
        if (!from.equals("Scan")) {
            byte[] httpRequest = httpReqResp.getRequest();
            int bodySize = httpRequest.length - info.getBodyOffset();
            if (bodySize > 0) {
                request.append(new String(httpRequest, info.getBodyOffset(), bodySize));
            }
        }
        // 请求头构建完成后，设置里面包含的变量
        return setupVariable(service, request.toString()).getBytes();
    }

    private List<String> getHeader() {
        if (!mDataBoardTab.hasReplaceHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getHeader();
    }

    private List<String> getExcludeHeader() {
        if (!mDataBoardTab.hasExcludeHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getExcludeHeader();
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
        String randomLocalIP = IPUtils.randomIPv4ForLocal();
        String randomUA = Utils.getRandomItem(WordlistManager.getUserAgent());
        String domainMain = DomainHelper.getDomain(domain);
        String domainName = DomainHelper.getDomainName(domain);
        String subdomain = getSubdomain(domain);
        // 替换变量
        request = request.replace("{{host}}", host);
        request = request.replace("{{domain}}", domain);
        request = request.replace("{{domain.main}}", domainMain);
        request = request.replace("{{domain.name}}", domainName);
        request = request.replace("{{subdomain}}", subdomain);
        request = request.replace("{{protocol}}", protocol);
        request = request.replace("{{timestamp}}", timestamp);
        request = request.replace("{{random.ip}}", randomIP);
        request = request.replace("{{random.local-ip}}", randomLocalIP);
        request = request.replace("{{random.ua}}", randomUA);
        return request;
    }

    /**
     * 获取子域名（如果没有子域名，则返回主域名的名称）
     *
     * @param domain 域名（格式示例：www.xxx.com）
     * @return 失败返回传入的domain参数
     */
    private String getSubdomain(String domain) {
        if (IPUtils.hasIPv4(domain)) {
            return domain;
        }
        if (!domain.contains(".")) {
            return domain;
        }
        return domain.split("\\.")[0];
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
        byte[] respBytes = httpReqResp.getResponse();
        // 获取所需要的参数
        String method = request.getMethod();
        URL url = request.getUrl();
        String host = getHostByUrl(url);
        String reqUrl = getReqUrl(url);
        String title = HtmlUtils.findTitleByHtmlBody(respBytes);
        String ip = findIpByHost(url.getHost());
        int status = -1;
        int length = -1;
        // 存在响应对象，获取状态和响应包大小
        if (respBytes != null && respBytes.length > 0) {
            IResponseInfo response = mHelpers.analyzeResponse(respBytes);
            status = response.getStatusCode();
            // 处理响应 body 的长度
            length = respBytes.length - response.getBodyOffset();
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
        byte[] respBytes = httpReqResp.getResponse();
        if (respBytes == null || respBytes.length == 0) {
            return;
        }
        // 保存路径
        String saveDir = Config.getFilePath(Config.KEY_JSON_FIELD_COLLECT_PATH, true);
        saveDir = saveDir + File.separator + domain;
        FileUtils.mkdirs(saveDir);
        String savePath = saveDir + File.separator + host + ".txt";
        // 解析响应
        IResponseInfo respInfo = mHelpers.analyzeResponse(respBytes);
        int bodyOffset = respInfo.getBodyOffset();
        int bodySize = respBytes.length - bodyOffset;
        // 检测响应包是否没有body内容
        if (bodySize <= 0) {
            return;
        }
        String respJson = new String(respBytes, bodyOffset, bodySize);
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
        mRequestTextEditor.setMessage("Loading...".getBytes(), true);
        mResponseTextEditor.setMessage("Loading...".getBytes(), false);
        new Thread(this::refreshReqRespMessage).start();
    }

    /**
     * 刷新请求响应信息
     */
    private synchronized void refreshReqRespMessage() {
        byte[] request = getRequest();
        byte[] response = getResponse();
        if (request == null || request.length == 0) {
            request = "".getBytes();
        }
        if (response == null || response.length == 0) {
            response = "".getBytes();
        }
        mRequestTextEditor.setMessage(request, true);
        mResponseTextEditor.setMessage(response, false);
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
            byte[] reqBytes = ((IHttpRequestResponse) data.getReqResp()).getRequest();
            String url = data.getHost() + data.getUrl();
            try {
                URL u = new URL(url);
                int port = u.getPort();
                boolean useHttps = "https".equalsIgnoreCase(u.getProtocol());
                if (port == -1) {
                    port = useHttps ? 443 : 80;
                }
                mCallbacks.sendToRepeater(u.getHost(), port, useHttps, reqBytes, null);
            } catch (Exception e) {
                Logger.debug(e.getMessage());
            }
        }
    }

    @Override
    public byte[] getBodyByTaskData(TaskData data) {
        if (data == null || data.getReqResp() == null) {
            return new byte[]{};
        }
        mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        byte[] respBytes = mCurrentReqResp.getResponse();
        if (respBytes == null || respBytes.length <= 0) {
            return new byte[]{};
        }
        IResponseInfo info = mCallbacks.getHelpers().analyzeResponse(respBytes);
        int offset = info.getBodyOffset();
        return Arrays.copyOfRange(respBytes, offset, respBytes.length);
    }

    @Override
    public void addToBlackHost(ArrayList<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return;
        }
        List<String> list = WordlistManager.getList(WordlistManager.KEY_BLACK_HOST);
        for (String host : hosts) {
            if (!list.contains(host)) {
                list.add(host);
            }
        }
        WordlistManager.putList(WordlistManager.KEY_BLACK_HOST, list);
        mOneScan.getConfigPanel().refreshHostTab();
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        switch (action) {
            case RequestTab.EVENT_QPS_LIMIT:
                changeQpsLimit(String.valueOf(params[0]));
                break;
            case OtherTab.EVENT_UNLOAD_PLUGIN:
                mCallbacks.unloadExtension();
                break;
            case DataBoardTab.EVENT_IMPORT_URL:
                importUrl((List<?>) params[0]);
                break;
            case DataBoardTab.EVENT_STOP_TASK:
                stopAllTask();
                break;
        }
    }

    private void changeQpsLimit(String limit) {
        mQpsLimit = new QpsLimiter(StringUtils.parseInt(limit));
        Logger.debug("Event: change qps limit: %s", limit);
    }

    private void importUrl(List<?> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        // 处理导入的 URL 数据
        new Thread(() -> {
            for (Object item : list) {
                try {
                    IHttpRequestResponse httpReqResp = new HttpReqRespAdapter(String.valueOf(item));
                    doScan(httpReqResp, "Import");
                } catch (IllegalArgumentException e) {
                    Logger.error("Import error: " + e.getMessage());
                }
            }
        }).start();
    }

    private void stopAllTask() {
        mThreadPool.shutdownNow();
        // 停止后，重新初始化线程池
        mThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        // 重新初始化 QPS 限制器
        initQpsLimiter();
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean editable) {
        return new OneScanInfoTab(mCallbacks);
    }
}
