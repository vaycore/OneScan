package burp.vaycore.onescan.ui.tab;

import burp.vaycore.common.layout.VLayout;
import burp.vaycore.onescan.ui.tab.config.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * 配置面板
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class ConfigPanel extends JTabbedPane {

    private PayloadTab mPayloadTab;
    private RequestTab mRequestTab;
    private HostTab mHostTab;
    private OtherTab mOtherTab;

    public ConfigPanel() {
        initView();
    }

    public String getTitleName() {
        return "Config";
    }

    private void initView() {
        mPayloadTab = new PayloadTab();
        mRequestTab = new RequestTab();
        mHostTab = new HostTab();
        mOtherTab = new OtherTab();
        addConfigTab(mPayloadTab);
        addConfigTab(mRequestTab);
        addConfigTab(mHostTab);
        addConfigTab(mOtherTab);
    }

    private void addConfigTab(BaseConfigTab tab) {
        JScrollPane scrollPane = new JScrollPane(tab);
        // 设置滚轮速度
        scrollPane.getVerticalScrollBar().setUnitIncrement(30);
        scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));
        addTab(tab.getTitleName(), scrollPane);
    }

    public PayloadTab getPayloadTab() {
        return mPayloadTab;
    }

    public RequestTab getRequestTab() {
        return mRequestTab;
    }

    public HostTab getHostTab() {
        return mHostTab;
    }

    public OtherTab getOtherTab() {
        return mOtherTab;
    }
}
