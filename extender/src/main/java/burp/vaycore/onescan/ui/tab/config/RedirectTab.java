package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.ui.base.BaseConfigTab;

import javax.swing.*;
import java.awt.event.ItemEvent;

/**
 * Redirect设置
 * <p>
 * Created by vaycore on 2025-06-13.
 */
public class RedirectTab extends BaseConfigTab {

    protected void initView() {
        addEnabledConfigPanel(L.get("cookies_follow"), L.get("cookies_follow_sub_title"),
                Config.KEY_REDIRECT_COOKIES_FOLLOW);
        addEnabledConfigPanel(L.get("target_host_limit"), L.get("target_host_limit_sub_title"),
                Config.KEY_REDIRECT_TARGET_HOST_LIMIT);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.redirect");
    }

    protected void addEnabledConfigPanel(String title, String subTitle, String configKey) {
        boolean state = Config.getBoolean(configKey);
        // 启用选项
        JPanel panel = new JPanel(new HLayout(10));
        JRadioButton enabledBtn = new JRadioButton(L.get("enabled"));
        panel.add(enabledBtn);
        enabledBtn.setSelected(state);
        // 禁用选项
        JRadioButton disabledBtn = new JRadioButton(L.get("disabled"));
        panel.add(disabledBtn);
        disabledBtn.setSelected(!state);
        UIHelper.createRadioGroup(enabledBtn, disabledBtn);
        // 选项变更，保存配置
        enabledBtn.addItemListener(e -> {
            int stateChange = e.getStateChange();
            boolean newState = stateChange == ItemEvent.SELECTED;
            Config.put(configKey, String.valueOf(newState));
        });
        addConfigItem(title, subTitle, panel);
    }
}