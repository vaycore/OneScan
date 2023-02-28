package burp.vaycore.onescan.ui.base;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.OnTabEventListener;
import burp.vaycore.onescan.ui.widget.SimpleWordlist;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;

/**
 * 通用配置页面基类
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public abstract class BaseConfigTab extends BaseTab {

    private OnTabEventListener mOnTabEventListener;

    @Override
    protected void initData() {
        setBorder(new EmptyBorder(5, 10, 5, 10));
        setLayout(new VFlowLayout());
    }

    @Override
    public abstract String getTitleName();

    /**
     * 添加配置项
     *
     * @param title    配置项标题
     * @param subTitle 配置项描述
     * @param layout   配置项布局
     */
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
        add(UIHelper.newDividerLine());
    }

    /**
     * 添加文本配置项
     *
     * @param title     配置项标题
     * @param subTitle  配置项说明
     * @param columns   文本框大概展示的文字数（宽度调整）
     * @param configKey 配置文件中的Key
     * @return 文件框组件对象
     */
    protected JTextField addTextConfigPanel(String title, String subTitle, int columns, String configKey) {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));
        JTextField textField = new JTextField(Config.get(configKey), columns);
        panel.add(textField);
        JButton button = new JButton("Save");
        button.addActionListener(e -> {
            boolean state = onTextConfigSave(configKey, textField.getText());
            if (state) {
                UIHelper.showTipsDialog("Save success!");
            }
        });
        panel.add(button);
        addConfigItem(title, subTitle, panel);
        return textField;
    }

    /**
     * 添加字典配置项
     *
     * @param title     配置项标题
     * @param subTitle  配置项说明
     * @param configKey 配置文件中的Key
     */
    protected void addWordListPanel(String title, String subTitle, String configKey) {
        SimpleWordlist wordlist = new SimpleWordlist(Config.getList(configKey));
        wordlist.setOnDataChangeListener(action -> {
            ArrayList<String> listData = wordlist.getListData();
            Config.putList(configKey, listData);
        });
        addConfigItem(title, subTitle, wordlist);
    }

    /**
     * 发送事件
     *
     * @param action 事件action
     */
    protected void sendTabEvent(String action) {
        this.sendTabEvent(action, "");
    }

    /**
     * 发送事件
     *
     * @param action 事件action
     * @param params 事件参数列表
     */
    protected void sendTabEvent(String action, Object... params) {
        if (mOnTabEventListener != null) {
            mOnTabEventListener.onTabEventMethod(action, params);
        }
    }

    /**
     * 设置事件监听
     *
     * @param l 事件监听接口
     */
    public void setOnTabEventListener(OnTabEventListener l) {
        this.mOnTabEventListener = l;
    }

    /**
     * 文本配置保存事件
     *
     * @param configKey 配置文件中的Key
     * @param text      输入框中的文本
     * @return 用户定义保存状态（true=保存成功；false=保存取消）
     */
    protected boolean onTextConfigSave(String configKey, String text) {
        return false;
    }
}
