package burp.hae;

import burp.*;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.hae.montoya.MontoyaApiImpl;
import burp.hae.montoya.http.HttpImpl;
import burp.hae.montoya.http.HttpRequestToBeSentImpl;
import burp.hae.montoya.http.HttpResponseReceivedImpl;
import burp.hae.montoya.http.HttpServiceImpl;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.OneScan;

import java.awt.*;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * HaE 插件对接
 * <p>
 * Created by vaycore on 2022-09-08.
 */
public class HaE {

    private static BurpExtender sExtender;
    private static IBurpExtenderCallbacks sCallbacks;
    private static BurpCallbacksAdapter sAdapter;
    private static MontoyaApi sMontoyaApi;
    private static IHttpListener sHttpListener;
    private static Component sMainUI;

    public static void init(BurpExtender extender) {
        sExtender = extender;
        sCallbacks = extender.getCallbacks();
    }

    /**
     * 加载插件
     *
     * @param pluginPath 插件jar包路径
     */
    public static void loadPlugin(String pluginPath) {
        HaE.loadPlugin(pluginPath, new LoadPluginCallback() {
            @Override
            public void onLoadSuccess() {

            }

            @Override
            public void onLoadError(String msg) {
                Logger.error(msg);
            }
        });
    }

    /**
     * 加载插件
     *
     * @param pluginPath 插件jar包路径
     * @param callback   加载插件回调接口实例
     */
    public static void loadPlugin(String pluginPath, LoadPluginCallback callback) {
        // 检测插件路径是否未配置
        if (StringUtils.isEmpty(pluginPath)) {
            return;
        }
        // 检测回调接口实例是否为空
        if (callback == null) {
            Logger.error("callback is null!");
            return;
        }
        // 是否初始化所需变量
        if (sExtender == null || sCallbacks == null) {
            callback.onLoadError("no init!");
            return;
        }
        // 检测 HaE 插件的路径是否正常
        if (!pluginPath.endsWith(".jar") || !FileUtils.isFile(pluginPath)) {
            callback.onLoadError("HaE plugin path invalid!");
            return;
        }
        try {
            sAdapter = new BurpCallbacksAdapter(sCallbacks);
            sAdapter.setExtensionFilename(pluginPath);
            // 监听 UI 组件设置（等 UI 设置之后，再对各项参数进行检测和初始化）
            sAdapter.setBurpUiComponentCallback((component) -> {
                // 检测插件名，是否为HaE
                String name = sAdapter.getExtensionName();
                if (StringUtils.isEmpty(name) || !name.contains("Highlighter and Extractor")) {
                    callback.onLoadError("Load plugin failed: plugin error, invalid plugin: " + name);
                    sAdapter.setBurpUiComponentCallback(null);
                    return;
                }
                sMainUI = component;
                OneScan oneScan = (OneScan) sExtender.getUiComponent();
                oneScan.addTab("HaE", sMainUI);
                UIHelper.refreshUI(oneScan);
                // 参数赋值
                sHttpListener = sAdapter.getHttpListener();
                Logger.info("HaE load success! info: %s", name);
                callback.onLoadSuccess();
            });
            // 监听主动卸载插件事件（直接调用 HaE.unloadPlugin 方法即可）
            sAdapter.setOnUnloadExtensionListener(HaE::unloadPlugin);
            // 初始化 HaE 插件
            initHaE(pluginPath);
        } catch (Exception e) {
            callback.onLoadError("HaE load exception: " + e);
        }
    }

    /**
     * 初始化 HaE 插件
     *
     * @param pluginPath 插件路径
     * @throws MalformedURLException  插件路径异常
     * @throws ClassNotFoundException 插件不包含要加载的类
     */
    private static void initHaE(String pluginPath) throws MalformedURLException, ClassNotFoundException {
        URL u = new File(pluginPath).toURI().toURL();
        ClassLoader loader = new URLClassLoader(new URL[]{u});
        Class<?> c;
        try {
            c = loader.loadClass("burp.BurpExtender");
            IBurpExtender extender = (IBurpExtender) ClassUtils.newObjectByClass(c);
            if (extender != null) {
                extender.registerExtenderCallbacks(sAdapter);
            } else {
                throw new IllegalStateException("BurpExtender load failed.");
            }
        } catch (ClassNotFoundException e) {
            // 尝试加载 HaE 3.0 版本入口
            c = loader.loadClass("hae.HaE");
            BurpExtension extension = (BurpExtension) ClassUtils.newObjectByClass(c);
            if (extension != null) {
                sMontoyaApi = new MontoyaApiImpl(sAdapter);
                extension.initialize(sMontoyaApi);
            } else {
                throw new IllegalStateException("BurpExtension load failed.");
            }
        }
    }

    /**
     * 卸载插件
     *
     * @return true=卸载成功；false=卸载失败
     */
    public static boolean unloadPlugin() {
        // 是否已安装插件
        if (!hasInstall()) {
            return false;
        }
        try {
            OneScan oneScan = (OneScan) sExtender.getUiComponent();
            if (oneScan == null) {
                return false;
            }
            oneScan.remove(sMainUI);
            UIHelper.refreshUI(oneScan);
            sAdapter.invokeExtensionStateListeners();
            sHttpListener = null;
            sMainUI = null;
            sMontoyaApi = null;
            sAdapter = null;
            System.gc();
            Logger.info("HaE unload success!");
            return true;
        } catch (Exception e) {
            Logger.error("HaE unload exception: %s", e.toString());
            return false;
        }
    }

    /**
     * 是否安装插件
     *
     * @return true=已安装；false=未安装
     */
    public static boolean hasInstall() {
        return sExtender != null &&
                sCallbacks != null &&
                sAdapter != null &&
                sMainUI != null;
    }

    /**
     * 处理 HTTP 请求、响应信息
     *
     * @param messageInfo 请求、响应信息实例
     */
    public static void processHttpMessage(IHttpRequestResponse messageInfo) {
        byte[] respRaw = messageInfo.getResponse();
        boolean messageIsRequest = respRaw == null || respRaw.length == 0;
        try {
            // 调用事件处理
            if (sHttpListener != null) {
                sHttpListener.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, messageInfo);
            } else if (sMontoyaApi != null) {
                montoyaProcessHttpMessage(messageIsRequest, messageInfo);
            }
        } catch (Exception e) {
            // 打印HaE处理时抛出的错误（为了不影响任务面板显示的请求结果）
            Logger.error("HaE plugin error: " + e);
        }
    }

    /**
     * 使 processHttpMessage 方法兼容 MontoyaAPI
     *
     * @param messageIsRequest 是否只是请求
     * @param messageInfo      请求响应信息实例
     */
    private static void montoyaProcessHttpMessage(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        byte[] respRaw = messageInfo.getResponse();
        HttpImpl http = (HttpImpl) sMontoyaApi.http();
        // 构建 Annotations 类
        String comment = messageInfo.getComment();
        String colorName = messageInfo.getHighlight();
        Annotations annotations = Annotations.annotations(comment, HighlightColor.highlightColor(colorName));
        // 构建 HttpRequest 类
        HttpServiceImpl service = new HttpServiceImpl(messageInfo.getHttpService());
        HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(messageInfo.getRequest()));
        HttpRequestToBeSentImpl sent = new HttpRequestToBeSentImpl(request, annotations, ToolType.PROXY);
        // 调用 Request 事件处理
        RequestToBeSentAction sentAction = http.httpHandler().handleHttpRequestToBeSent(sent);
        // 构建 HttpResponse 类
        annotations = sentAction.annotations();
        if (messageIsRequest) {
            respRaw = new byte[0];
        }
        HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(respRaw));
        HttpResponseReceivedImpl received = new HttpResponseReceivedImpl(request, response,
                annotations, ToolType.PROXY);
        // 调用 Response 事件处理
        ResponseReceivedAction receivedAction = http.httpHandler().handleHttpResponseReceived(received);
        annotations = receivedAction.annotations();
        // HaE 高亮
        comment = annotations.notes();
        colorName = annotations.highlightColor().displayName().toLowerCase();
        messageInfo.setComment(comment);
        messageInfo.setHighlight(colorName);
    }

    /**
     * 加载插件回调
     */
    public interface LoadPluginCallback {

        /**
         * 加载成功
         */
        void onLoadSuccess();

        /**
         * 加载错误
         *
         * @param msg 错误信息
         */
        void onLoadError(String msg);
    }
}
