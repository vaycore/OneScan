package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.hae.HaE;
import burp.vaycore.onescan.common.Config;
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

    private JTextField mWebNameCollectPath;
    private JTextField mJsonFieldCollectPath;
    private JTextField mHaEPluginPath;

    @Override
    protected void initView() {
        addConfigItem("Web name collect", "Select a file path", newWebNameCollectPanel());
        addConfigItem("Json field collect", "Select a directory path", newJsonFieldCollectPanel());
        addConfigItem("HaE", "Set HaE plugin file path", newHaEPluginPathPanel());
    }

    @Override
    public String getTitleName() {
        return "Other";
    }

    private JPanel newWebNameCollectPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));

        mWebNameCollectPath = new JTextField(getWebNameCollectPath(), 35);
        mWebNameCollectPath.setEditable(false);
        panel.add(mWebNameCollectPath);

        JButton button = new JButton("Select file...");
        button.setActionCommand("web-name-collect-select-file");
        button.addActionListener(this);
        panel.add(button);
        return panel;
    }

    private JPanel newJsonFieldCollectPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));

        mJsonFieldCollectPath = new JTextField(getJsonFieldCollectPath(), 35);
        mJsonFieldCollectPath.setEditable(false);
        panel.add(mJsonFieldCollectPath);

        JButton button = new JButton("Select directory...");
        button.setActionCommand("json-field-collect-select-dir");
        button.addActionListener(this);
        panel.add(button);
        return panel;
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

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        String oldPath;
        String filepath;
        boolean state;
        switch (action) {
            case "web-name-collect-select-file":
                oldPath = getWebNameCollectPath();
                filepath = UIHelper.selectFileDialog("Select a file", oldPath);
                if (StringUtils.isEmpty(filepath) || oldPath.equals(filepath)) {
                    return;
                }
                mWebNameCollectPath.setText(filepath);
                Config.put(Config.KEY_WEB_NAME_COLLECT_PATH, filepath);
                break;
            case "json-field-collect-select-dir":
                oldPath = getJsonFieldCollectPath();
                filepath = UIHelper.selectDirDialog("Select a directory", oldPath);
                if (StringUtils.isEmpty(filepath) || oldPath.equals(filepath)) {
                    return;
                }
                mJsonFieldCollectPath.setText(filepath);
                Config.put(Config.KEY_JSON_FIELD_COLLECT_PATH, filepath);
                break;
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
            default:
                break;
        }
    }

    private String getWebNameCollectPath() {
        return Config.getFilePath(Config.KEY_WEB_NAME_COLLECT_PATH);
    }

    private String getJsonFieldCollectPath() {
        return Config.getFilePath(Config.KEY_JSON_FIELD_COLLECT_PATH, true);
    }

    private String getHaEPluginPath() {
        String path = Config.get(Config.KEY_HAE_PLUGIN_PATH);
        if (StringUtils.isEmpty(path)) {
            return "";
        }
        return path;
    }
}
