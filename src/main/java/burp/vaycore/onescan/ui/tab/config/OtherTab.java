package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.hae.HaE;
import burp.vaycore.onescan.common.Config;
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
        addFileConfigPanel("Web name collect", "Select a file path", Config.KEY_WEB_NAME_COLLECT_PATH);
        addDirectoryConfigPanel("Json field collect", "Select a directory path", Config.KEY_JSON_FIELD_COLLECT_PATH);
        addDirectoryConfigPanel("Wordlist Directory", "Set Wordlist directory path", Config.KEY_WORDLIST_PATH);
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
        boolean state;
        switch (action) {
            case "hae-plugin-select-file":
                oldPath = getHaEPluginPath();
                filepath = UIHelper.selectFileDialog("Select a file", oldPath);
                if (StringUtils.isEmpty(filepath) || oldPath.equals(filepath)) {
                    return;
                }
                mHaEPluginPath.setText(filepath);
                Config.put(Config.KEY_HAE_PLUGIN_PATH, filepath);
                state = HaE.loadPlugin(filepath);
                if (state) {
                    UIHelper.showTipsDialog("HaE load success!");
                }
                break;
            case "hae-plugin-unload":
                state = HaE.unloadPlugin();
                if (state) {
                    mHaEPluginPath.setText("");
                    Config.put(Config.KEY_HAE_PLUGIN_PATH, "");
                    UIHelper.showTipsDialog("HaE unload success!");
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
}
