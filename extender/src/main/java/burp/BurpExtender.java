package burp;

import burp.hae.HaE;
import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.common.helper.QpsLimiter;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.onescan.OneScan;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.*;
import burp.vaycore.onescan.info.OneScanInfoTab;
import burp.vaycore.onescan.manager.CollectManager;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.tab.DataBoardTab;
import burp.vaycore.onescan.ui.tab.config.OtherTab;
import burp.vaycore.onescan.ui.tab.config.RequestTab;
import burp.vaycore.onescan.ui.widget.TaskTable;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.onescan.ui.widget.payloadlist.ProcessingItem;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, ITab, OnTabEventListener, IMessageEditorTabFactory,
        IExtensionStateListener, IContextMenuFactory {

    /**
     * 任务线程数量
     */
    private static final int TASK_THREAD_COUNT = 50;

    /**
     * 指纹识别线程数量
     */
    private static final int FP_THREAD_COUNT = 10;

    /**
     * 空字节数组常量（防止频繁创建）
     */
    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * 去重过滤集合
     */
    private final Set<String> sRepeatFilter = Collections.synchronizedSet(new HashSet<>(500000));

    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private OneScan mOneScan;
    private DataBoardTab mDataBoardTab;
    private IMessageEditor mRequestTextEditor;
    private IMessageEditor mResponseTextEditor;
    private ExecutorService mThreadPool;
    private ExecutorService mFpThreadPool;
    private ExecutorService mRefreshMsgTask;
    private IHttpRequestResponse mCurrentReqResp;
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
        this.mRefreshMsgTask = Executors.newSingleThreadExecutor();
        this.mCallbacks.setExtensionName(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
        // 初始化日志打印
        Logger.init(Constants.DEBUG, mCallbacks.getStdout(), mCallbacks.getStderr());
        // 初始化默认配置
        Config.init(getWorkDir());
        // 初始化域名辅助类
        DomainHelper.init("public_suffix_list.json");
        // 初始化HaE插件
        HaE.init(this);
        // 初始化QPS限制器
        initQpsLimiter();
        // 注册 OneScan 信息辅助面板
        this.mCallbacks.registerMessageEditorTabFactory(this);
        // 注册插件卸载监听器
        this.mCallbacks.registerExtensionStateListener(this);
    }

    /**
     * 获取工作目录路径（优先获取当前插件 jar 包所在目录配置文件，如果配置不存在，则使用默认工作目录）
     */
    private String getWorkDir() {
        String workDir = Paths.get(mCallbacks.getExtensionFilename())
                .getParent().toString() + File.separator + "OneScan" + File.separator;
        if (FileUtils.isDir(workDir)) {
            return workDir;
        }
        return null;
    }

    /**
     * 初始化 QPS 限制器
     */
    private void initQpsLimiter() {
        // 检测范围，如果不符合条件，不创建限制器
        int limit = StringUtils.parseInt(Config.get(Config.KEY_QPS_LIMIT));
        int delay = StringUtils.parseInt(Config.get(Config.KEY_REQUEST_DELAY));
        if (limit > 0 && limit <= 9999) {
            this.mQpsLimit = new QpsLimiter(limit, delay);
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
        mCallbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> items = new ArrayList<>();
        // 扫描选定目标
        JMenuItem sendToOneScanItem = new JMenuItem(L.get("send_to_plugin"));
        items.add(sendToOneScanItem);
        sendToOneScanItem.addActionListener((event) -> new Thread(() -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            for (IHttpRequestResponse httpReqResp : messages) {
                doScan(httpReqResp, "Send");
                // 线程池关闭后，停止发送扫描任务
                if (mThreadPool.isShutdown()) {
                    Logger.debug("sendToPlugin: thread pool is shutdown, stop sending scan task");
                    return;
                }
            }
        }).start());
        // 选择 Payload 扫描
        List<String> payloadList = WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD);
        if (!payloadList.isEmpty() && payloadList.size() > 1) {
            JMenu menu = new JMenu(L.get("use_payload_scan"));
            items.add(menu);
            ActionListener listener = (event) -> new Thread(() -> {
                String action = event.getActionCommand();
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                for (IHttpRequestResponse httpReqResp : messages) {
                    doScan(httpReqResp, "Send", action);
                    // 线程池关闭后，停止发送扫描任务
                    if (mThreadPool.isShutdown()) {
                        Logger.debug("usePayloadScan: thread pool is shutdown, stop sending scan task");
                        return;
                    }
                }
            }).start();
            for (String itemName : payloadList) {
                JMenuItem item = new JMenuItem(itemName);
                item.setActionCommand(itemName);
                item.addActionListener(listener);
                menu.add(item);
            }
        }
        return items;
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
        String item = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        doScan(httpReqResp, from, item);
    }

    private void doScan(IHttpRequestResponse httpReqResp, String from, String payloadItem) {
        if (httpReqResp == null || httpReqResp.getHttpService() == null) {
            return;
        }
        IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
        String host = httpReqResp.getHttpService().getHost();
        // 对来自代理的包进行检测，检测请求方法是否需要拦截
        if (from.equals("Proxy")) {
            String method = info.getMethod();
            if (includeMethodFilter(method)) {
                // 拦截不匹配的请求方法
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return;
            }
            // 检测 Host 是否在白名单、黑名单列表中
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return;
            }
            // 收集数据（只收集代理流量的数据）
            CollectManager.collect(true, host, httpReqResp.getRequest());
            CollectManager.collect(false, host, httpReqResp.getResponse());
        }
        // 准备生成任务
        URL url = getUrlByRequestInfo(info);
        // 原始请求也需要经过 Payload Process 处理（不过需要过滤一些后缀的流量）
        if (!proxyExcludeSuffixFilter(url)) {
            runScanTask(httpReqResp, info, null, from);
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
        // 检测是否禁用递归扫描
        if (!mDataBoardTab.hasDirScan()) {
            return;
        }
        // 获取一下请求数据包中的请求路径
        String reqPath = getReqPathByRequestInfo(info);
        // 从请求路径中，尝试获取请求主机地址
        String reqHost = getReqHostByReqPath(reqPath);
        Logger.debug("doScan receive: %s%s", getReqHostByUrl(url), url.getPath());
        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        List<String> payloads = WordlistManager.getPayload(payloadItem);
        // 一级目录一级目录递减访问
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            String path = pathDict.get(i);
            // 拼接字典，发起请求
            for (String item : payloads) {
                if (path.endsWith("/")) {
                    path = path.substring(0, path.length() - 1);
                }
                String urlPath = path + item;
                // 检测一下是否携带完整的 Host 地址（兼容一下携带了完整的 Host 地址的情况）
                if (reqPath.startsWith("http")) {
                    urlPath = reqHost + urlPath;
                }
                runScanTask(httpReqResp, info, urlPath, "Scan");
            }
        }
    }

    /**
     * 从 IRequestInfo 实例中读取请求行中的请求路径
     *
     * @param info IRequestInfo 实例
     * @return 不存在返回空字符串
     */
    private String getReqPathByRequestInfo(IRequestInfo info) {
        if (info == null) {
            return "";
        }
        // 获取请求行
        List<String> headers = info.getHeaders();
        if (!headers.isEmpty()) {
            String reqLine = headers.get(0);
            Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
            if (matcher.find() && matcher.groupCount() >= 1) {
                return matcher.group(1);
            }
        }
        return "";
    }

    /**
     * 从请求路径中（有些站点请求路径中包含完整的 Host 地址）获取请求的 Host 地址
     *
     * @param reqPath 请求路径
     * @return 不包含 Host 地址，返回空字符串
     */
    private String getReqHostByReqPath(String reqPath) {
        if (StringUtils.isEmpty(reqPath)) {
            return "";
        }
        try {
            URL url = new URL(reqPath);
            return getReqHostByUrl(url);
        } catch (MalformedURLException e) {
            return "";
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
    private boolean hostAllowlistFilter(String host) {
        List<String> list = WordlistManager.getHostAllowlist();
        // 白名单为空，不启用白名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                return false;
            }
        }
        Logger.debug("hostAllowlistFilter filter host: %s", host);
        return true;
    }

    /**
     * Host黑名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostBlocklistFilter(String host) {
        List<String> list = WordlistManager.getHostBlocklist();
        // 黑名单为空，不启用黑名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                Logger.debug("hostBlocklistFilter filter host: %s （rule: %s）", host, item);
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

    /**
     * 使用 '/' 分割 URL 实例的 path 数据，通过组合第一层级目录，生成字典列表
     *
     * @param urlPath URL 实例的 path 数据
     * @return 失败返回空列表
     */
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
    private void runScanTask(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {
        IHttpService service = httpReqResp.getHttpService();
        // 处理请求头
        byte[] request = handleHeader(httpReqResp, info, pathWithQuery, from);
        // 处理请求头失败时，丢弃该任务
        if (request == null) {
            return;
        }
        IRequestInfo newInfo = mHelpers.analyzeRequest(service, request);
        String url = getReqHostByHttpService(service) + newInfo.getUrl().getPath();
        // 如果当前 URL 已经扫描，中止任务
        if (sRepeatFilter.contains(url)) {
            return;
        }
        // 如果未启用“请求包处理”功能，直接对扫描的任务发起请求
        if (!mDataBoardTab.hasPayloadProcessing()) {
            doBurpRequest(service, url, request, from);
            return;
        }
        // 运行已经启用并且需要合并的任务
        runEnableAndMergeTask(service, url, request, from);
        // 运行已经启用并且不需要合并的任务
        runEnabledWithoutMergeProcessingTask(service, url, request);
    }

    /**
     * 运行已经启用并且需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param url         请求URL
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void runEnableAndMergeTask(IHttpService service, String url, byte[] reqRawBytes, String from) {
        // 获取已经启用并且需要合并的“请求包处理”规则
        List<ProcessingItem> processList = getPayloadProcess()
                .stream().filter(ProcessingItem::isEnabledAndMerge)
                .collect(Collectors.toList());
        // 先检测规则是否为空
        if (processList.isEmpty()) {
            doBurpRequest(service, url, reqRawBytes, from);
            return;
        }
        byte[] resultBytes = reqRawBytes;
        for (ProcessingItem item : processList) {
            ArrayList<PayloadItem> items = item.getItems();
            resultBytes = handlePayloadProcess(service, resultBytes, items);
        }
        if (resultBytes != null) {
            // 检测是否未进行任何处理
            boolean equals = Arrays.equals(reqRawBytes, resultBytes);
            // 未进行任何处理时，不变更 from 值
            String newFrom = equals ? from : from + "（Process）";
            doBurpRequest(service, url, resultBytes, newFrom);
        } else {
            // 如果规则处理异常导致数据返回为空，则发送原来的请求
            doBurpRequest(service, url, reqRawBytes, from);
        }
    }

    /**
     * 运行已经启用并且不需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param url         请求URL
     * @param reqRawBytes 请求数据包
     */
    private void runEnabledWithoutMergeProcessingTask(IHttpService service, String url, byte[] reqRawBytes) {
        // 遍历规则列表，进行 Payload Processing 处理后，再次请求数据包
        getPayloadProcess().parallelStream().filter(ProcessingItem::isEnabledWithoutMerge)
                .forEach((item) -> {
                    ArrayList<PayloadItem> items = item.getItems();
                    byte[] requestBytes = handlePayloadProcess(service, reqRawBytes, items);
                    // 因为不需要合并的规则是将每条处理完成的数据包都发送请求，所以规则处理异常的请求包，不需要发送请求
                    if (requestBytes == null) {
                        return;
                    }
                    // 检测是否未进行任何处理（如上所述的原因，未进行任何处理的请求包，也不需要发送请求）
                    boolean equals = Arrays.equals(reqRawBytes, requestBytes);
                    if (equals) {
                        return;
                    }
                    doBurpRequest(service, url, requestBytes, "Process" + "（" + item.getName() + "）");
                });
    }

    /**
     * 使用Burp自带的方式请求
     *
     * @param service     请求目标服务实例
     * @param url         请求URL
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void doBurpRequest(IHttpService service, String url, byte[] reqRawBytes, String from) {
        // 线程池关闭后，不接收任何任务
        if (mThreadPool.isShutdown()) {
            Logger.debug("doBurpRequest: thread pool is shutdown, intercept url: %s", url);
            return;
        }
        // 将 URL 添加到去重过滤集合
        sRepeatFilter.add(url);
        // 创建任务运行实例
        TaskRunnable task = new TaskRunnable(url) {
            @Override
            public void run() {
                // 限制QPS
                if (mQpsLimit != null) {
                    try {
                        mQpsLimit.limit();
                    } catch (InterruptedException e) {
                        // 线程强制停止时，将未执行的任务从去重过滤集合中移除
                        sRepeatFilter.remove(url);
                        return;
                    }
                }
                Logger.debug("Do Send Request url: %s", url);
                // 动态变量赋值
                String reqRaw = mHelpers.bytesToString(reqRawBytes);
                reqRaw = setupVariable(service, url, reqRaw);
                if (reqRaw == null) {
                    // 动态变量处理异常，丢弃当前请求
                    return;
                }
                // 请求配置的请求重试次数
                int retryCount = getReqRetryCount();
                // 发起请求
                byte[] newReqRawBytes = mHelpers.stringToBytes(reqRaw);
                IHttpRequestResponse newReqResp = doMakeHttpRequest(service, url, newReqRawBytes, retryCount);
                // HaE提取信息
                HaE.processHttpMessage(newReqResp);
                // 构建展示的数据包
                TaskData data = buildTaskData(newReqResp);
                // 用于过滤代理数据包
                data.setFrom(from);
                mDataBoardTab.getTaskTable().addTaskData(data);
                // 收集数据
                CollectManager.collect(false, service.getHost(), newReqResp.getResponse());
            }
        };
        // 将任务添加线程池
        try {
            mThreadPool.execute(task);
        } catch (Exception e) {
            Logger.error("doBurpRequest thread execute error: %s", e.getMessage());
        }
    }

    /**
     * 调用 BurpSuite 请求方式
     *
     * @param service     请求目标服务实例
     * @param reqUrl      请求URL
     * @param reqRawBytes 请求数据包
     * @param retryCount  重试次数（为0表示不重试）
     * @return 请求响应数据
     */
    private IHttpRequestResponse doMakeHttpRequest(IHttpService service, String reqUrl,
                                                   byte[] reqRawBytes, int retryCount) {
        IHttpRequestResponse reqResp;
        try {
            reqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);
            byte[] respRawBytes = reqResp.getResponse();
            if (respRawBytes != null && respRawBytes.length > 0) {
                return reqResp;
            }
        } catch (Exception e) {
            Logger.debug("Do Request error, url: %s", reqUrl);
            reqResp = new HttpReqRespAdapter(reqUrl);
            reqResp.setRequest(reqRawBytes);
            reqResp.setResponse(new byte[0]);
        }
        Logger.debug("Check retry url: %s, count: %d", reqUrl, retryCount);
        // 检测是否需要重试
        if (retryCount <= 0) {
            return reqResp;
        }
        try {
            // 重试前先延迟
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            // 如果线程中断，返回目前的响应结果
            return reqResp;
        }
        // 请求重试
        return doMakeHttpRequest(service, reqUrl, reqRawBytes, retryCount - 1);
    }

    /**
     * 处理请求头
     *
     * @param httpReqResp   Burp 的 HTTP 请求响应接口
     * @param pathWithQuery 请求路径，或者请求路径+Query（示例：/xxx、/xxx/index?a=xxx&b=xxx）
     * @param from          数据来源
     * @return 处理完成的数据包，失败时返回null
     */
    private byte[] handleHeader(IHttpRequestResponse httpReqResp, IRequestInfo info, String pathWithQuery, String from) {
        IHttpService service = httpReqResp.getHttpService();
        // 配置的请求头
        List<String> configHeader = getHeader();
        // 要移除的请求头KEY列表
        List<String> removeHeaders = getRemoveHeaders();
        // 数据包自带的请求头
        List<String> headers = info.getHeaders();
        // 构建请求头
        StringBuilder requestRaw = new StringBuilder();
        // 根据数据来源区分两种请求头
        if (from.equals("Scan")) {
            requestRaw.append("GET ").append(pathWithQuery).append(" HTTP/1.1").append("\r\n");
        } else {
            String reqLine = headers.get(0);
            // 先检测一下是否包含 ' HTTP/' 字符串，再继续处理（可能有些畸形数据包不存在该内容）
            if (reqLine.contains(" HTTP/")) {
                int start = reqLine.lastIndexOf(" HTTP/");
                reqLine = reqLine.substring(0, start) + " HTTP/1.1";
            }
            requestRaw.append(reqLine).append("\r\n");
        }
        // 请求头的参数处理（顺带处理移除的请求头）
        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            String key = item.split(": ")[0];
            // 是否需要移除当前请求头字段（优先级最高）
            if (removeHeaders.contains(key)) {
                continue;
            }
            // 如果是扫描的请求（只有 GET 请求），将 Content-Length 移除
            if (from.equals("Scan") && "Content-Length".equalsIgnoreCase(key)) {
                continue;
            }
            // 检测配置中是否存在当前请求头字段
            List<String> matchList = configHeader.stream().filter(configHeaderItem -> {
                if (StringUtils.isNotEmpty(configHeaderItem) && configHeaderItem.contains(": ")) {
                    String configHeaderKey = configHeaderItem.split(": ")[0];
                    // 检测是否需要移除当前请求头字段
                    if (removeHeaders.contains(key)) {
                        return false;
                    }
                    return configHeaderKey.equals(key);
                }
                return false;
            }).collect(Collectors.toList());
            // 配置中存在匹配项，替换为配置中的数据
            if (!matchList.isEmpty()) {
                for (String matchItem : matchList) {
                    requestRaw.append(matchItem).append("\r\n");
                }
                // 将已经添加的数据从列表中移除
                configHeader.removeAll(matchList);
            } else {
                // 不存在匹配项，填充原数据
                requestRaw.append(item).append("\r\n");
            }
        }
        // 将配置里剩下的值全部填充到请求头中
        for (String item : configHeader) {
            String key = item.split(": ")[0];
            // 检测是否需要移除当前KEY
            if (removeHeaders.contains(key)) {
                continue;
            }
            requestRaw.append(item).append("\r\n");
        }
        requestRaw.append("\r\n");
        // 如果当前数据来源不是 Scan，可能会包含 POST 请求，判断是否存在 body 数据
        if (!from.equals("Scan")) {
            byte[] httpRequest = httpReqResp.getRequest();
            int bodyOffset = info.getBodyOffset();
            int bodySize = httpRequest.length - bodyOffset;
            if (bodySize > 0) {
                requestRaw.append(new String(httpRequest, bodyOffset, bodySize));
            }
        }
        // 请求头构建完成后，对里面包含的动态变量进行赋值
        String newRequestRaw = setupVariable(service, info.getUrl(), requestRaw.toString());
        if (newRequestRaw == null) {
            return null;
        }
        return mHelpers.stringToBytes(newRequestRaw);
    }

    /**
     * 获取请求头配置
     */
    private List<String> getHeader() {
        if (!mDataBoardTab.hasReplaceHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getHeader();
    }

    /**
     * 获取移除请求头列表配置
     */
    private List<String> getRemoveHeaders() {
        if (!mDataBoardTab.hasRemoveHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getRemoveHeaders();
    }

    /**
     * 获取配置的 Payload Processing 规则
     */
    private List<ProcessingItem> getPayloadProcess() {
        ArrayList<ProcessingItem> list = Config.getPayloadProcessList();
        if (list == null) {
            return new ArrayList<>();
        }
        return list.stream().filter(ProcessingItem::isEnabled).collect(Collectors.toList());
    }

    /**
     * 从配置中获取请求重试次数
     */
    private int getReqRetryCount() {
        String value = Config.get(Config.KEY_RETRY_COUNT);
        return StringUtils.parseInt(value, 0);
    }

    /**
     * 给数据包填充动态变量
     *
     * @param service    请求目标实例
     * @param url        请求 url 字符串
     * @param requestRaw 请求数据包字符串
     * @return 处理失败返回null
     */
    private String setupVariable(IHttpService service, String url, String requestRaw) {
        URL u = UrlUtils.parseURL(url);
        if (u == null) {
            return null;
        }
        return setupVariable(service, u, requestRaw);
    }

    /**
     * 给数据包填充动态变量
     *
     * @param service    请求目标实例
     * @param url        请求 URL 实例
     * @param requestRaw 请求数据包字符串
     * @return 处理失败返回null
     */
    private String setupVariable(IHttpService service, URL url, String requestRaw) {
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
        String domainMain = DomainHelper.getDomain(domain, null);
        String domainName = DomainHelper.getDomainName(domain, null);
        String subdomain = getSubdomain(domain);
        String webroot = getWebrootByURL(url);
        // 替换变量
        try {
            requestRaw = fillVariable(requestRaw, "host", host);
            requestRaw = fillVariable(requestRaw, "domain", domain);
            requestRaw = fillVariable(requestRaw, "domain.main", domainMain);
            requestRaw = fillVariable(requestRaw, "domain.name", domainName);
            requestRaw = fillVariable(requestRaw, "subdomain", subdomain);
            requestRaw = fillVariable(requestRaw, "protocol", protocol);
            requestRaw = fillVariable(requestRaw, "timestamp", timestamp);
            requestRaw = fillVariable(requestRaw, "random.ip", randomIP);
            requestRaw = fillVariable(requestRaw, "random.local-ip", randomLocalIP);
            requestRaw = fillVariable(requestRaw, "random.ua", randomUA);
            requestRaw = fillVariable(requestRaw, "webroot", webroot);
            // 填充日期、时间相关的动态变量
            if (requestRaw.contains("{{date.") || requestRaw.contains("{{time.")) {
                String currentDate = DateUtils.getCurrentDate("yyyy-MM-dd HH:mm:ss;yy-M-d H:m:s");
                String[] split = currentDate.split(";");
                String[] leftDateTime = parseDateTime(split[0]);
                requestRaw = fillVariable(requestRaw, "date.yyyy", leftDateTime[0]);
                requestRaw = fillVariable(requestRaw, "date.MM", leftDateTime[1]);
                requestRaw = fillVariable(requestRaw, "date.dd", leftDateTime[2]);
                requestRaw = fillVariable(requestRaw, "time.HH", leftDateTime[3]);
                requestRaw = fillVariable(requestRaw, "time.mm", leftDateTime[4]);
                requestRaw = fillVariable(requestRaw, "time.ss", leftDateTime[5]);
                String[] rightDateTime = parseDateTime(split[1]);
                requestRaw = fillVariable(requestRaw, "date.yy", rightDateTime[0]);
                requestRaw = fillVariable(requestRaw, "date.M", rightDateTime[1]);
                requestRaw = fillVariable(requestRaw, "date.d", rightDateTime[2]);
                requestRaw = fillVariable(requestRaw, "time.H", rightDateTime[3]);
                requestRaw = fillVariable(requestRaw, "time.m", rightDateTime[4]);
                requestRaw = fillVariable(requestRaw, "time.s", rightDateTime[5]);
            }
            return requestRaw;
        } catch (IllegalArgumentException e) {
            Logger.debug(e.getMessage());
            return null;
        }
    }

    /**
     * 填充动态变量
     *
     * @param src   数据源
     * @param name  变量名
     * @param value 需要填充的变量值
     * @throws IllegalArgumentException 当填充的变量值为空时，抛出该异常
     */
    private String fillVariable(String src, String name, String value) throws IllegalArgumentException {
        if (StringUtils.isEmpty(src)) {
            return src;
        }
        String key = String.format("{{%s}}", name);
        if (!src.contains(key)) {
            return src;
        }
        // 值为空时，返回null值丢弃当前请求
        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException(key + " fill failed, value is empty.");
        }
        return src.replace(key, value);
    }

    /**
     * 解析日期时间，将每个字段的数据存入数组
     *
     * @param dateTime 日期时间字符串（格式：yyyy-MM-dd HH:mm:ss 或者 yy-M-d H:m:s）
     * @return [0]=年；[1]=月；[2]=日；[3]=时；[4]=分；[5]=秒
     */
    private String[] parseDateTime(String dateTime) {
        String[] result = new String[6];
        String[] split = dateTime.split(" ");
        // 日期
        String date = split[0];
        String[] dateSplit = date.split("-");
        result[0] = dateSplit[0];
        result[1] = dateSplit[1];
        result[2] = dateSplit[2];
        // 时间
        String time = split[1];
        String[] timeSplit = time.split(":");
        result[3] = timeSplit[0];
        result[4] = timeSplit[1];
        result[5] = timeSplit[2];
        return result;
    }

    /**
     * 获取子域名（如果没有子域名，则返回主域名的名称）
     *
     * @param domain 域名（格式示例：www.xxx.com）
     * @return 失败返回null值
     */
    private String getSubdomain(String domain) {
        if (IPUtils.hasIPv4(domain)) {
            return null;
        }
        if (!domain.contains(".")) {
            return null;
        }
        return domain.split("\\.")[0];
    }

    /**
     * 从URL实例中获取Web根目录名（例如："http://xxx.com/abc/a.php" => "abc"）
     *
     * @param url URL实例
     * @return 失败返回null
     */
    private String getWebrootByURL(URL url) {
        String path = url.getPath();
        // 没有根目录名，直接返回null
        if (StringUtils.isEmpty(path) || "/".equals(path)) {
            return null;
        }
        // 找第二个'/'斜杠
        int end = path.indexOf("/", 1);
        if (end < 0) {
            return null;
        }
        // 找到之后，取中间的值
        return path.substring(1, end);
    }

    /**
     * 根据 Payload Process 规则，处理数据包
     *
     * @param service      请求目标服务
     * @param requestBytes 请求数据包
     * @return 处理后的数据包
     */
    private byte[] handlePayloadProcess(IHttpService service, byte[] requestBytes, List<PayloadItem> list) {
        if (requestBytes == null || requestBytes.length == 0) {
            return null;
        }
        if (list == null || list.isEmpty()) {
            return null;
        }
        IRequestInfo info = mHelpers.analyzeRequest(service, requestBytes);
        int bodyOffset = info.getBodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = UrlUtils.toURI(info.getUrl());
        String header = new String(requestBytes, 0, bodyOffset - 4);
        String body = bodySize <= 0 ? "" : new String(requestBytes, bodyOffset, bodySize);
        String request = mHelpers.bytesToString(requestBytes);
        for (PayloadItem item : list) {
            // 只调用启用的规则
            PayloadRule rule = item.getRule();
            try {
                switch (item.getScope()) {
                    case PayloadRule.SCOPE_URL:
                        String newUrl = rule.handleProcess(url);
                        // 截取请求头第一行，用于定位要处理的位置
                        String reqLine = header.substring(0, header.indexOf("\r\n"));
                        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
                        if (matcher.find()) {
                            int start = matcher.start(1);
                            int end = matcher.end(1);
                            // 分隔要插入数据的位置
                            String left = header.substring(0, start);
                            String right = header.substring(end);
                            // 拼接处理好的数据
                            header = left + newUrl + right;
                            request = header + "\r\n\r\n" + body;
                        }
                        url = newUrl;
                        break;
                    case PayloadRule.SCOPE_HEADER:
                        String newHeader = rule.handleProcess(header);
                        header = newHeader;
                        request = newHeader + "\r\n\r\n" + body;
                        break;
                    case PayloadRule.SCOPE_BODY:
                        String newBody = rule.handleProcess(body);
                        request = header + "\r\n\r\n" + newBody;
                        body = newBody;
                        break;
                    case PayloadRule.SCOPE_REQUEST:
                        request = rule.handleProcess(request);
                        break;
                }
            } catch (Exception e) {
                Logger.debug("handlePayloadProcess exception: " + e.getMessage());
                return null;
            }
        }
        // 更新 Content-Length
        return updateContentLength(mHelpers.stringToBytes(request));
    }

    /**
     * 更新 Content-Length 参数值
     *
     * @param rawBytes 请求数据包
     * @return 更新后的数据包
     */
    private byte[] updateContentLength(byte[] rawBytes) {
        String request = new String(rawBytes, StandardCharsets.US_ASCII);
        int bodyOffset = request.indexOf("\r\n\r\n");
        if (bodyOffset == -1) {
            Logger.error("Handle payload process error: bodyOffset is -1");
            return null;
        }
        bodyOffset += 4;
        int bodySize = rawBytes.length - bodyOffset;
        if (bodySize < 0) {
            Logger.error("Handle payload process error: bodySize < 0");
            return null;
        } else if (bodySize == 0) {
            return rawBytes;
        }
        String header = new String(rawBytes, 0, bodyOffset - 4);
        if (!header.contains("Content-Length")) {
            header += "\r\nContent-Length: " + bodySize;
        } else {
            header = header.replaceAll("Content-Length:.*", "Content-Length: " + bodySize);
        }
        String body = new String(rawBytes, bodyOffset, bodySize);
        request = header + "\r\n\r\n" + body;
        return request.getBytes(StandardCharsets.UTF_8);
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
        String reqHost = getReqHostByUrl(url);
        String reqUrl = url.getFile();
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
        data.setHost(reqHost);
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

    /**
     * 通过 IHttpService 实例，获取请求的 Host 地址（http://xxxxxx.com、http://xxxxxx.com:8080）
     *
     * @param service IHttpService 实例
     * @return 返回请求的 Host 地址
     */
    private String getReqHostByHttpService(IHttpService service) {
        String protocol = service.getProtocol();
        String host = service.getHost();
        int port = service.getPort();
        return concatReqHost(protocol, host, port);
    }

    /**
     * 通过 URL 实例，获取请求的 Host 地址（http://xxxxxx.com、http://xxxxxx.com:8080）
     *
     * @param url URL 实例
     * @return 返回请求的 Host 地址
     */
    private String getReqHostByUrl(URL url) {
        String protocol = url.getProtocol();
        String host = url.getHost();
        int port = url.getPort();
        return concatReqHost(protocol, host, port);
    }

    /**
     * 拼接请求的 Host 地址（示例：http://xxxxxx.com、http://xxxxxx.com:8080）
     *
     * @param protocol 协议
     * @param host     主机
     * @param port     端口号
     * @return 返回拼接完成的 Host 地址
     */
    private String concatReqHost(String protocol, String host, int port) {
        if (port < 0 || port == 80 || port == 443 || port > 65535) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    /**
     * 根据 Host 查询 IP 地址
     *
     * @param host Host 值
     * @return 失败返回空字符串
     */
    private String findIpByHost(String host) {
        if (IPUtils.hasIPv4(host)) {
            return host;
        }
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * 获取 IRequestInfo 实例的请求 URL 实例
     *
     * @param info IRequestInfo 实例
     * @return 返回请求的 URL 实例
     */
    private URL getUrlByRequestInfo(IRequestInfo info) {
        URL url = info.getUrl();
        try {
            // IRequestInfo.getUrl 方法有时候获取的值不准确，重新解析一下
            url = new URL(url.toString());
            return url;
        } catch (Exception e) {
            Logger.error("getUrlByRequestInfo: convert url error: %s", e.getMessage());
        }
        return url;
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
        // 如果 data 为空，表示执行了清空历史记录操作
        if (data == null) {
            onClearHistory();
            return;
        }
        mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
        // 加载请求、响应数据包
        byte[] hintBytes = mHelpers.stringToBytes(L.get("message_editor_loading"));
        mRequestTextEditor.setMessage(hintBytes, true);
        mResponseTextEditor.setMessage(hintBytes, false);
        mRefreshMsgTask.execute(this::refreshReqRespMessage);
    }

    /**
     * 清空历史记录
     */
    private void onClearHistory() {
        mCurrentReqResp = null;
        // 清空去重过滤集合
        sRepeatFilter.clear();
        // 清空显示的请求、响应数据包
        mRequestTextEditor.setMessage(EMPTY_BYTES, true);
        mResponseTextEditor.setMessage(EMPTY_BYTES, false);
    }

    /**
     * 刷新请求响应信息
     */
    private void refreshReqRespMessage() {
        byte[] request = getRequest();
        byte[] response = getResponse();
        if (request == null || request.length == 0) {
            request = EMPTY_BYTES;
        }
        if (response == null || response.length == 0) {
            response = EMPTY_BYTES;
        }
        // 检测是否超过配置的显示长度限制
        int maxLength = StringUtils.parseInt(Config.get(Config.KEY_MAX_DISPLAY_LENGTH));
        if (maxLength >= 100000 && request.length >= maxLength) {
            String hint = L.get("message_editor_request_length_limit_hint");
            request = mHelpers.stringToBytes(hint);
        }
        if (maxLength >= 100000 && response.length >= maxLength) {
            String hint = L.get("message_editor_response_length_limit_hint");
            response = mHelpers.stringToBytes(hint);
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
        if (respBytes == null || respBytes.length == 0) {
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
        List<String> list = WordlistManager.getList(WordlistManager.KEY_HOST_BLOCKLIST);
        for (String host : hosts) {
            if (!list.contains(host)) {
                list.add(host);
            }
        }
        WordlistManager.putList(WordlistManager.KEY_HOST_BLOCKLIST, list);
        mOneScan.getConfigPanel().refreshHostTab();
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        switch (action) {
            case RequestTab.EVENT_QPS_LIMIT:
                changeQpsLimit(String.valueOf(params[0]));
                break;
            case RequestTab.EVENT_REQUEST_DELAY:
                changeRequestDelay(String.valueOf(params[0]));
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

    /**
     * 修改 QPS 限制
     *
     * @param limit QPS 限制值（数字）
     */
    private void changeQpsLimit(String limit) {
        initQpsLimiter();
        Logger.debug("Event: change qps limit: %s", limit);
    }

    /**
     * 修改请求延迟
     *
     * @param delay 延迟的值（数字）
     */
    private void changeRequestDelay(String delay) {
        initQpsLimiter();
        Logger.debug("Event: change request delay: %s", delay);
    }

    /**
     * 导入URL
     *
     * @param list URL列表
     */
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
                // 线程池关闭后，停止导入 Url 数据
                if (mThreadPool.isShutdown()) {
                    Logger.debug("importUrl: thread pool is shutdown, stop import url");
                    return;
                }
            }
        }).start();
    }

    /**
     * 停止扫描中的所有任务
     */
    private void stopAllTask() {
        // 关闭线程池，处理未执行的任务
        List<Runnable> taskList = mThreadPool.shutdownNow();
        for (Runnable run : taskList) {
            if (run instanceof TaskRunnable) {
                TaskRunnable task = (TaskRunnable) run;
                String taskUrl = task.getTaskUrl();
                // 将未执行的任务从去重过滤集合中移除
                sRepeatFilter.remove(taskUrl);
            }
        }
        // 提示信息
        UIHelper.showTipsDialog(L.get("stop_task_tips"));
        // 停止后，重新初始化线程池
        mThreadPool = Executors.newFixedThreadPool(TASK_THREAD_COUNT);
        // 重新初始化 QPS 限制器
        initQpsLimiter();
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean editable) {
        return new OneScanInfoTab(mCallbacks);
    }

    @Override
    public void extensionUnloaded() {
        // 卸载 HaE 插件
        HaE.unloadPlugin();
        // 移除代理监听器
        mCallbacks.removeProxyListener(this);
        // 移除插件卸载监听器
        mCallbacks.removeExtensionStateListener(this);
        // 移除信息辅助面板
        mCallbacks.removeMessageEditorTabFactory(this);
        // 移除注册的菜单
        mCallbacks.removeContextMenuFactory(this);
        // 关闭任务线程池
        int count = mThreadPool.shutdownNow().size();
        Logger.info("Close: task thread pool completed. Task %d records.", count);
        // 关闭指纹识别线程池
        count = mFpThreadPool.shutdownNow().size();
        Logger.info("Close: fingerprint recognition thread pool completed. Task %d records.", count);
        // 关闭数据收集线程池
        count = CollectManager.closeThreadPool();
        Logger.info("Close: data collection thread pool completed. Task %d records.", count);
        // 清除去重过滤集合
        count = sRepeatFilter.size();
        sRepeatFilter.clear();
        Logger.info("Clear: repeat filter list completed. Total %d records.", count);
        // 清除任务列表
        count = 0;
        if (mDataBoardTab != null && mDataBoardTab.getTaskTable() != null) {
            count = mDataBoardTab.getTaskTable().getTaskCount();
            mDataBoardTab.getTaskTable().clearAll();
            // 关闭导入 URL 窗口
            mDataBoardTab.closeImportUrlWindow();
        }
        Logger.info("Clear: task list completed. Total %d records.", count);
        // 清除指纹识别缓存
        count = FpManager.getCacheCount();
        FpManager.clearCache();
        Logger.info("Clear: fingerprint recognition cache completed. Total %d records.", count);
        // 清除数据收集的去重过滤集合
        count = CollectManager.getRepeatFilterCount();
        CollectManager.clearRepeatFilter();
        Logger.info("Clear: data collection repeat filter list completed. Total %d records.", count);
        // 卸载完成
        Logger.info(Constants.UNLOAD_BANNER);
    }
}