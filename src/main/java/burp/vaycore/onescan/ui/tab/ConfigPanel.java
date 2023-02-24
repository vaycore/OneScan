package burp.vaycore.onescan.ui.tab;

import burp.vaycore.onescan.common.OnTabEventListener;
import burp.vaycore.onescan.ui.tab.config.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * 配置面板
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class ConfigPanel extends JTabbedPane implements OnTabEventListener {

    private OnTabEventListener mOnTabEventListener;

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

    /**
     * 添加配置页面Tab
     *
     * @param tab 配置页面布局
     */
    private void addConfigTab(BaseConfigTab tab) {
        tab.setOnTabEventListener(this);
        JScrollPane scrollPane = new JScrollPane(tab);
        // 设置滚轮速度
        scrollPane.getVerticalScrollBar().setUnitIncrement(30);
        scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));
        addTab(tab.getTitleName(), scrollPane);
    }

    public void setOnTabEventListener(OnTabEventListener l) {
        this.mOnTabEventListener = l;
    }

    @Override
    public void onTabEventMethod(String action, Object... params) {
        if (this.mOnTabEventListener != null) {
            this.mOnTabEventListener.onTabEventMethod(action, params);
        }
    }
}
