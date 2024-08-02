package burp.vaycore.onescan.ui.tab.config;

import burp.hae.HaE;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
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
        addTextConfigPanel("Maximum display length", "Set the maximum display length of the editor（default: 0）",
                20, Config.KEY_MAX_DISPLAY_LENGTH).addKeyListener(new NumberFilter(8));
        addDirectoryConfigPanel("Collect directory", "Set Collect directory path", Config.KEY_COLLECT_PATH);
        addDirectoryConfigPanel("Wordlist directory", "Set Wordlist directory path", Config.KEY_WORDLIST_PATH);
        addConfigItem("HaE", "Set HaE plugin file path", newHaEPluginPathPanel());
        addConfigItem("Clear Temp", "Clear fingerprint check temp", newFpClearTempPanel());
    }

    @Override
    public String getTitleName() {
        return "Other";
    }

    private JPanel newHaEPluginPathPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));
        mHaEPluginPath = new JTextField(getHaEPluginPath(), 35);
        mHaEPluginPath.setEditable(false);
        panel.add(mHaEPluginPath);
        JButton button = new JButton("Select file...");
        button.setActionCommand("hae-plugin-select-file");
        button.addActionListener(this);
        panel.add(button);
        JButton unload = new JButton("Unload");
        unload.setActionCommand("hae-plugin-unload");
        unload.addActionListener(this);
        panel.add(unload);
        return panel;
    }

    private JPanel newFpClearTempPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout());
        JButton button = new JButton("Clear");
        button.setActionCommand("clear-fingerprint-check-temp");
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
                    UIHelper.showTipsDialog("HaE plugin already loaded.");
                    return;
                }
                filepath = UIHelper.selectFileDialog("Select a file", oldPath);
                if (StringUtils.isEmpty(filepath) || oldPath.equals(filepath)) {
                    return;
                }
                mHaEPluginPath.setText(filepath);
                HaE.loadPlugin(filepath, new HaE.LoadPluginCallback() {
                    @Override
                    public void onLoadSuccess() {
                        UIHelper.showTipsDialog("HaE load success!");
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
                    UIHelper.showTipsDialog("HaE unload success!");
                } else {
                    UIHelper.showTipsDialog("HaE unload failed!");
                }
                break;
            case "clear-fingerprint-check-temp":
                String count = FpManager.getTempCount();
                if ("0".equals(count)) {
                    UIHelper.showTipsDialog("Temp is empty.");
                    return;
                }
                String msg = String.format("存在%s条指纹识别缓存，是否清空缓存？", count);
                int ret = UIHelper.showOkCancelDialog(msg);
                if (ret == 0) {
                    FpManager.clearTemp();
                    UIHelper.showTipsDialog("Clear success.");
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
                UIHelper.showTipsDialog("Invalid maximum display length value.(range: 100000-99999999)");
                return false;
            }
            text = String.valueOf(value);
            Config.put(configKey, text);
            return true;
        }
        return super.onTextConfigSave(configKey, text);
    }
}
