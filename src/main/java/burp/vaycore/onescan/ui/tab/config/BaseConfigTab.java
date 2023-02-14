package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.ui.base.BaseTab;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * 通用配置页面基类
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public abstract class BaseConfigTab extends BaseTab {

    @Override
    protected void initData() {
        setBorder(new EmptyBorder(5, 10, 5, 10));
        setLayout(new VLayout(5));
    }

    @Override
    protected void initView() {

    }

    @Override
    public abstract String getTitleName();

    protected void addConfigItem(String title, String subTitle, Component... layout) {
        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(16f).deriveFont(Font.BOLD));
        label.setBorder(new EmptyBorder(5, 3, 5, 0));
        label.setForeground(Color.decode("#FF6633"));
        add(label);

        if (StringUtils.isNotEmpty(subTitle)) {
            JLabel subTitleLabel = new JLabel(subTitle);
            subTitleLabel.setBorder(new EmptyBorder(0, 3, 5, 0));
            add(subTitleLabel);
        }

        // 添加配置内容组件
        for (Component component : layout) {
            if (component != null) {
                add(component);
            }
        }
        add(new JPanel(), "10px");
        add(newDividerLine());
    }

    protected JPanel newDividerLine() {
        JPanel panel = new JPanel();
        panel.setPreferredSize(new Dimension(0, 1));
        panel.setOpaque(true);
        panel.setBackground(Color.LIGHT_GRAY);
        return panel;
    }
}
