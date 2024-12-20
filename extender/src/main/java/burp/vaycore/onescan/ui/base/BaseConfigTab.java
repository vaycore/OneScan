package burp.vaycore.onescan.ui.base;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.PopupMenuListenerAdapter;
import burp.vaycore.onescan.manager.CollectManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.tab.config.OtherTab;
import burp.vaycore.onescan.ui.widget.SimpleWordlist;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.regex.Pattern;

/**
 * 通用配置页面基类
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public abstract class BaseConfigTab extends BaseTab {

    private static final Pattern NAME_REGEX = Pattern.compile("[\\w]+");

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
        JButton button = new JButton(L.get("save"));
        button.addActionListener(e -> {
            boolean state = onTextConfigSave(configKey, textField.getText());
            if (state) {
                UIHelper.showTipsDialog(L.get("save_success"));
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
        JButton button = new JButton(L.get("select_file"));
        button.addActionListener((e) -> {
            String oldPath = Config.getFilePath(configKey);
            String newPath = UIHelper.selectFileDialog(L.get("select_a_file"), oldPath);
            if (!StringUtils.isEmpty(newPath) && !oldPath.equals(newPath)) {
                textField.setText(newPath);
                Config.put(configKey, newPath);
                UIHelper.showTipsDialog(L.get("save_success"));
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
        JButton button = new JButton(L.get("select_directory"));
        button.addActionListener((e) -> {
            String oldPath = Config.getFilePath(configKey, true);
            String newPath = UIHelper.selectDirDialog(L.get("select_a_directory"), oldPath);
            if (!StringUtils.isEmpty(newPath) && !oldPath.equals(newPath)) {
                textField.setText(newPath);
                Config.put(configKey, newPath);
                // 配置额外处理
                try {
                    if (configKey.equals(Config.KEY_WORDLIST_PATH)) {
                        WordlistManager.init(newPath, true);
                        UIHelper.showTipsDialog(L.get("wordlist_directory_save_success"));
                        sendTabEvent(OtherTab.EVENT_UNLOAD_PLUGIN);
                        return;
                    } else if (configKey.equals(Config.KEY_COLLECT_PATH)) {
                        CollectManager.init(newPath);
                    }
                    UIHelper.showTipsDialog(L.get("save_success"));
                } catch (Exception ex) {
                    UIHelper.showTipsDialog(ex.getMessage());
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
        panel.setLayout(new HLayout(5, true));
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
            wordlist.setListData(list);
        });
        panel.add(cb, "290px");
        JButton newBtn = new JButton(L.get("new"));
        newBtn.addActionListener((e) -> newWordlist(cb, configKey, null));
        panel.add(newBtn, "65px");
        JButton deleteBtn = new JButton(L.get("delete"));
        deleteBtn.addActionListener((e) -> deleteWordlist(cb, wordlist, configKey));
        panel.add(deleteBtn, "75px");
        this.addConfigItem(title, subTitle, wordlist, panel);
    }

    /**
     * 创建新字典
     */
    private void newWordlist(JComboBox<String> cb, String configKey, String name) {
        JPanel panel = new JPanel(new VLayout(5));
        panel.setPreferredSize(new Dimension(300, 50));
        panel.add(new JLabel(L.get("please_enter_a_name")));
        JTextField textField = new JTextField(name);
        panel.add(textField);
        int ret = UIHelper.showCustomDialog(L.get("new_wordlist"), panel);
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        try {
            name = textField.getText();
            boolean check = NAME_REGEX.matcher(name).matches();
            if (!check) {
                throw new IllegalArgumentException(L.get("new_wordlist_value_invalid"));
            }
            WordlistManager.createList(configKey, name);
            // 切换到新创建的字典
            cb.addItem(name);
            cb.setSelectedItem(name);
        } catch (Exception e) {
            UIHelper.showTipsDialog(L.get("error_hint", e.getMessage()));
            newWordlist(cb, configKey, name);
        }
    }

    /**
     * 删除字典
     */
    private void deleteWordlist(JComboBox<String> cb, SimpleWordlist wordlist, String configKey) {
        String name = String.valueOf(cb.getSelectedItem());
        int ret = UIHelper.showOkCancelDialog(L.get("delete_wordlist_dialog_title"),
                L.get("delete_wordlist_dialog_hint", name));
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        try {
            // 清空字典列表UI里的数据
            wordlist.setListData(new ArrayList<>());
            WordlistManager.deleteList(configKey, name);
            List<String> itemList = WordlistManager.getItemList(configKey);
            // 随机选中一个
            String nextName = Utils.getRandomItem(itemList);
            if (StringUtils.isNotEmpty(nextName)) {
                cb.setSelectedItem(nextName);
            } else {
                cb.removeAllItems();
                // 整个目录清空完成，将 item 恢复为 default
                WordlistManager.putItem(configKey, "default");
            }
        } catch (Exception e) {
            UIHelper.showTipsDialog(L.get("error_hint", e.getMessage()));
        }
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
