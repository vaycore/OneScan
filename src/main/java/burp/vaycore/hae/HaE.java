package burp.vaycore.hae;

import burp.*;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.OneScan;

import java.awt.*;
import java.io.File;
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
     * @return true=加载成功；false=加载失败
     */
    public static boolean loadPlugin(String pluginPath) {
        // 是否初始化
        if (sExtender == null || sCallbacks == null) {
            return false;
        }
        // 检测HaE插件的路径是否正常
        if (StringUtils.isEmpty(pluginPath) || !FileUtils.isFile(pluginPath)) {
            return false;
        }
        try {
            URL u = new File(pluginPath).toURI().toURL();
            ClassLoader loader = new URLClassLoader(new URL[]{u});
            Class<?> c = loader.loadClass("burp.BurpExtender");
            IBurpExtender extender = (IBurpExtender) c.newInstance();
            sAdapter = new BurpCallbacksAdapter(sCallbacks);
            // 监听 UI 组件设置
            sAdapter.setBurpUiComponentCallback((component) -> {
                sMainUI = component;
                OneScan oneScan = (OneScan) sExtender.getUiComponent();
                oneScan.addTab("HaE", sMainUI);
                UIHelper.refreshUI(oneScan);
            });
            extender.registerExtenderCallbacks(sAdapter);
            // 检测插件名，是否为HaE
            String name = sAdapter.getExtensionName();
            if (StringUtils.isEmpty(name) || !name.contains("Highlighter and Extractor")) {
                throw new IllegalStateException("Load plugin failed: plugin error.");
            }
            // 参数赋值
            sHttpListener = sAdapter.getHttpListener();
            Logger.info("HaE load success! info: %s", name);
            return true;
        } catch (Exception e) {
            Logger.info("HaE load exception: %s", e.toString());
            return false;
        }
    }

    /**
     * 卸载插件
     *
     * @return true=卸载成功；false=卸载失败
     */
    public static boolean unloadPlugin() {
        // 是否初始化
        if (sExtender == null || sCallbacks == null || sAdapter == null) {
            return false;
        }
        try {
            OneScan oneScan = (OneScan) sExtender.getUiComponent();
            if (oneScan == null || sMainUI == null) {
                return false;
            }
            oneScan.remove(sMainUI);
            UIHelper.refreshUI(oneScan);
            sHttpListener = null;
            sMainUI = null;
            sAdapter = null;
            System.gc();
            Logger.info("HaE unload success!");
            return true;
        } catch (Exception e) {
            Logger.info("HaE unload exception: %s", e.toString());
            return false;
        }
    }

    public static void processHttpMessage(IHttpRequestResponse messageInfo) {
        if (sHttpListener != null) {
            byte[] response = messageInfo.getResponse();
            boolean messageIsRequest = response == null || response.length == 0;
            try {
                // 调用进行处理
                sHttpListener.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, messageInfo);
            } catch (Exception e) {
                // 打印HaE处理时抛出的错误（为了不影响任务面板显示的请求结果）
                Logger.error("HaE plugin error: " + e);
            }
        }
    }
}
