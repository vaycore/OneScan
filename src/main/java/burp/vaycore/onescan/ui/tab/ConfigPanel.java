package burp.vaycore.onescan.ui.tab;

import burp.vaycore.onescan.ui.tab.config.*;

import javax.swing.*;

/**
 * 配置面板
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class ConfigPanel extends JTabbedPane {

    public ConfigPanel() {
        initView();
    }

    public String getTitleName() {
        return "Config";
    }

    private void initView() {
        addConfigTab(new PayloadTab());
        addConfigTab(new RequestTab());
        addConfigTab(new HostTab());
        addConfigTab(new OtherTab());
    }

    private void addConfigTab(BaseConfigTab tab) {
        addTab(tab.getTitleName(), tab);
    }
}
