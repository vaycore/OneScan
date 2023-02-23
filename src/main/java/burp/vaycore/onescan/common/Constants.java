package burp.vaycore.onescan.common;

/**
 * 常量
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public interface Constants {

    // 插件信息
    String PLUGIN_NAME = "OneScan";
    String PLUGIN_VERSION = "0.4.3";
    boolean DEBUG = false;

    // 插件启动显示的信息
    String BANNER = "" +
            "#################################\n" +
            "  " + PLUGIN_NAME + " v" + PLUGIN_VERSION + "\n" +
            "  Author:    One\n" +
            "  Developer: vaycore\n" +
            "#################################\n";
}
