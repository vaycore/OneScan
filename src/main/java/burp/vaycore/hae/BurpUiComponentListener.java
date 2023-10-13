package burp.vaycore.hae;

import java.awt.*;

/**
 * UI 组件设置监听器
 * <p>
 * Created by k1n0 on 2023-10-12.
 */
public interface BurpUiComponentListener {

    /**
     * 组件设置事件
     *
     * @param component 组件实例
     */
    void onSetupUiComponent(Component component);
}
