package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.NumberFilter;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.ui.base.BaseConfigTab;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Other设置
 * <p>
 * Created by vaycore on 2022-08-21.
 */
public class OtherTab extends BaseConfigTab implements ActionListener {

    public static final String EVENT_UNLOAD_PLUGIN = "event-unload-plugin";

    protected void initView() {
        // 请求响应最大长度
        addTextConfigPanel(L.get("maximum_display_length"), L.get("maximum_display_length_sub_title"),
                20, Config.KEY_MAX_DISPLAY_LENGTH).addKeyListener(new NumberFilter(8));
        addDirectoryConfigPanel(L.get("collect_directory"), L.get("collect_directory_sub_title"), Config.KEY_COLLECT_PATH);
        addDirectoryConfigPanel(L.get("wordlist_directory"), L.get("wordlist_directory_sub_title"), Config.KEY_WORDLIST_PATH);
        addConfigItem(L.get("clear_cache"), L.get("clear_cache_sub_title"), newFpClearTempPanel());
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.other");
    }

    private JPanel newFpClearTempPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout());
        JButton button = new JButton(L.get("clear"));
        button.setActionCommand("clear-fingerprint-check-cache");
        button.addActionListener(this);
        panel.add(button);
        return panel;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        switch (action) {
            case "clear-fingerprint-check-cache":
                int count = FpManager.getCacheCount();
                if (count == 0) {
                    UIHelper.showTipsDialog(L.get("cache_is_empty"));
                    return;
                }
                int ret = UIHelper.showOkCancelDialog(L.get("clear_cache_dialog_message", count));
                if (ret == 0) {
                    FpManager.clearCache();
                    FpManager.clearHistory();
                    UIHelper.showTipsDialog(L.get("clear_success"));
                }
                break;
            default:
                break;
        }
    }

    @Override
    protected boolean onTextConfigSave(String configKey, String text) {
        int value = StringUtils.parseInt(text, -1);
        if (Config.KEY_MAX_DISPLAY_LENGTH.equals(configKey)) {
            if (value == 0) {
                text = String.valueOf(value);
                Config.put(configKey, text);
                return true;
            }
            if (value < 100000 || value > 99999999) {
                UIHelper.showTipsDialog(L.get("maximum_display_length_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
            Config.put(configKey, text);
            return true;
        }
        return super.onTextConfigSave(configKey, text);
    }
}
