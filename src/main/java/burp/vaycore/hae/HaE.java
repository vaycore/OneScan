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
            URL u = new File(pluginPath).toURI().toURL();
            ClassLoader loader = new URLClassLoader(new URL[]{u});
            Class<?> c = loader.loadClass("burp.BurpExtender");
            IBurpExtender extender = (IBurpExtender) c.newInstance();
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
            extender.registerExtenderCallbacks(sAdapter);
        } catch (Exception e) {
            callback.onLoadError("HaE load exception: " + e);
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
            sHttpListener = null;
            sMainUI = null;
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
