package burp.vaycore.onescan.ui.tab.config;

import burp.hae.HaE;
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

    private JTextField mHaEPluginPath;
    public static final String EVENT_UNLOAD_PLUGIN = "event-unload-plugin";

    protected void initView() {
        // 请求响应最大长度
        addTextConfigPanel(L.get("maximum_display_length"), L.get("maximum_display_length_sub_title"),
                20, Config.KEY_MAX_DISPLAY_LENGTH).addKeyListener(new NumberFilter(8));
        addDirectoryConfigPanel(L.get("collect_directory"), L.get("collect_directory_sub_title"), Config.KEY_COLLECT_PATH);
        addDirectoryConfigPanel(L.get("wordlist_directory"), L.get("wordlist_directory_sub_title"), Config.KEY_WORDLIST_PATH);
        addConfigItem(L.get("hae"), L.get("hae_sub_title"), newHaEPluginPathPanel());
        addConfigItem(L.get("clear_cache"), L.get("clear_cache_sub_title"), newFpClearTempPanel());
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.other");
    }

    private JPanel newHaEPluginPathPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));
        mHaEPluginPath = new JTextField(getHaEPluginPath(), 35);
        mHaEPluginPath.setEditable(false);
        panel.add(mHaEPluginPath);
        JButton button = new JButton(L.get("select_file"));
        button.setActionCommand("hae-plugin-select-file");
        button.addActionListener(this);
        panel.add(button);
        JButton unload = new JButton(L.get("unload"));
        unload.setActionCommand("hae-plugin-unload");
        unload.addActionListener(this);
        panel.add(unload);
        return panel;
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
        String oldPath;
        String filepath;
        switch (action) {
            case "hae-plugin-select-file":
                oldPath = getHaEPluginPath();
                if (HaE.hasInstall()) {
                    UIHelper.showTipsDialog(L.get("hae_plugin_already_loaded"));
                    return;
                }
                filepath = UIHelper.selectFileDialog(L.get("select_a_file"), oldPath);
                if (StringUtils.isEmpty(filepath) || oldPath.equals(filepath)) {
                    return;
                }
                mHaEPluginPath.setText(filepath);
                HaE.loadPlugin(filepath, new HaE.LoadPluginCallback() {
                    @Override
                    public void onLoadSuccess() {
                        UIHelper.showTipsDialog(L.get("hae_load_success"));
                        Config.put(Config.KEY_HAE_PLUGIN_PATH, filepath);
                    }

                    @Override
                    public void onLoadError(String msg) {
                        UIHelper.showTipsDialog(msg);
                        mHaEPluginPath.setText("");
                        Config.put(Config.KEY_HAE_PLUGIN_PATH, "");
                    }
                });
                break;
            case "hae-plugin-unload":
                boolean state = HaE.unloadPlugin();
                if (state) {
                    mHaEPluginPath.setText("");
                    Config.put(Config.KEY_HAE_PLUGIN_PATH, "");
                    UIHelper.showTipsDialog(L.get("hae_unload_success"));
                } else if (!HaE.hasInstall()) {
                    UIHelper.showTipsDialog(L.get("hae_not_installed"));
                } else {
                    UIHelper.showTipsDialog(L.get("hae_unload_failed"));
                }
                break;
            case "clear-fingerprint-check-cache":
                int count = FpManager.getCacheCount();
                if (count == 0) {
                    UIHelper.showTipsDialog(L.get("cache_is_empty"));
                    return;
                }
                int ret = UIHelper.showOkCancelDialog(L.get("clear_cache_dialog_message", count));
                if (ret == 0) {
                    FpManager.clearCache();
                    UIHelper.showTipsDialog(L.get("clear_success"));
                }
                break;
            default:
                break;
        }
    }

    private String getHaEPluginPath() {
        String path = Config.get(Config.KEY_HAE_PLUGIN_PATH);
        if (StringUtils.isEmpty(path)) {
            return "";
        }
        return path;
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
