package burp.vaycore.onescan.common;

/**
 * Tab页面事件监听
 * <p>
 * Created by vaycore on 2023-02-23.
 */
public interface OnTabEventListener {

    /**
     * Tab事件方法
     *
     * @param action 事件action
     * @param params 事件带的参数
     */
    void onTabEventMethod(String action, Object... params);
}
