package burp.vaycore.onescan.ui.base;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.OnDataChangeListener;
import burp.vaycore.onescan.common.PopupMenuListenerAdapter;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.tab.config.OtherTab;
import burp.vaycore.onescan.ui.widget.SimpleWordlist;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import java.awt.*;
import java.util.List;
import java.util.Vector;

/**
 * 通用配置页面基类
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public abstract class BaseConfigTab extends BaseTab {

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
     * 添加文件配置项
     *
     * @param title     配置项标题
     * @param subTitle  配置项说明
     * @param configKey 配置文件中的Key
     */
    protected void addFileConfigPanel(String title, String subTitle, String configKey) {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));
        String filePath = Config.getFilePath(configKey);
        JTextField textField = new JTextField(filePath, 35);
        textField.setEditable(false);
        panel.add(textField);
        JButton button = new JButton("Select file...");
        button.addActionListener((e) -> {
            String oldPath = Config.getFilePath(configKey);
            String newPath = UIHelper.selectFileDialog("Select a file", oldPath);
            if (!StringUtils.isEmpty(newPath) && !oldPath.equals(newPath)) {
                textField.setText(newPath);
                Config.put(configKey, newPath);
                UIHelper.showTipsDialog("Save success!");
            }
        });
        panel.add(button);
        this.addConfigItem(title, subTitle, panel);
    }

    /**
     * 添加目录配置项
     *
     * @param title     配置项标题
     * @param subTitle  配置项说明
     * @param configKey 配置文件中的Key
     */
    protected void addDirectoryConfigPanel(String title, String subTitle, String configKey) {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));
        String dirPath = Config.getFilePath(configKey);
        JTextField textField = new JTextField(dirPath, 35);
        textField.setEditable(false);
        panel.add(textField);
        JButton button = new JButton("Select directory...");
        button.addActionListener((e) -> {
            String oldPath = Config.getFilePath(configKey, true);
            String newPath = UIHelper.selectDirDialog("Select a directory", oldPath);
            if (!StringUtils.isEmpty(newPath) && !oldPath.equals(newPath)) {
                textField.setText(newPath);
                Config.put(configKey, newPath);
                // 对这个配置额外处理
                if (configKey.equals(Config.KEY_WORDLIST_PATH)) {
                    WordlistManager.init(newPath, true);
                    UIHelper.showTipsDialog("保存成功，需要重新加载插件");
                    sendTabEvent(OtherTab.EVENT_UNLOAD_PLUGIN);
                } else {
                    UIHelper.showTipsDialog("Save success!");
                }
            }
        });
        panel.add(button);
        this.addConfigItem(title, subTitle, panel);
    }

    /**
     * 添加字典配置项
     *
     * @param title     配置项标题
     * @param subTitle  配置项说明
     * @param configKey 配置文件中的Key
     */
    protected void addWordListPanel(String title, String subTitle, String configKey) {
        SimpleWordlist wordlist = new SimpleWordlist(WordlistManager.getList(configKey));
        wordlist.setOnDataChangeListener((action) -> {
            java.util.List<String> listData = wordlist.getListData();
            WordlistManager.putList(configKey, listData);
        });
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(0, true));
        JComboBox<String> cb = new JComboBox<>(new Vector<>(WordlistManager.getItemList(configKey)));
        cb.setSelectedItem(WordlistManager.getItem(configKey));
        cb.addPopupMenuListener(new PopupMenuListenerAdapter() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                List<String> configItems = WordlistManager.getItemList(configKey);
                String curItem = (String) cb.getSelectedItem();
                cb.removeAllItems();
                cb.addItem(curItem);
                for (String item : configItems) {
                    if (!item.equals(curItem)) {
                        cb.addItem(item);
                    }
                }
            }
        });
        cb.addItemListener((e) -> {
            String item = e.getItem().toString();
            String oldItem = WordlistManager.getItem(configKey);
            if (oldItem.equals(item)) {
                return;
            }
            WordlistManager.putItem(configKey, item);
            List<String> list = WordlistManager.getList(configKey);
            // 切换时数据量过大，可能造成卡顿，先临时取消监听器；设置完成数据后再添加回来
            OnDataChangeListener old = wordlist.getOnDataChangeListener();
            wordlist.setOnDataChangeListener(null);
            wordlist.setListData(list);
            wordlist.setOnDataChangeListener(old);
            old.onDataChange(wordlist.getActionCommand());
        });
        panel.add(cb, "440px");
        this.addConfigItem(title, subTitle, wordlist, panel);
    }

    /**
     * 文本配置保存事件
     *
     * @param configKey 配置文件中的Key
     * @param text      输入框中的文本
     * @return 用户定义保存状态（true=保存成功；false=保存取消）
     */
    protected boolean onTextConfigSave(String configKey, String text) {
        Config.put(configKey, text);
        return true;
    }

    /**
     * 重新初始化页面
     */
    public void reInitView() {
        removeAll();
        initView();
    }
}
