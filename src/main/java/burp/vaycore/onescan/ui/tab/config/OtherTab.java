package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.QpsLimiter;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.hae.HaE;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.NumberFilter;
import burp.vaycore.onescan.common.OnTabEventListener;

import javax.swing.*;
import java.awt.event.*;

/**
 * Other设置
 * <p>
 * Created by vaycore on 2022-08-21.
 */
public class OtherTab extends BaseConfigTab implements ActionListener {

    /**
     * limit 变量值变更事件
     */
    public static final String EVENT_QPS_LIMIT = "event-qps-limit";

    private JTextField mWebNameCollectPath;
    private JTextField mJsonFieldCollectPath;
    private JTextField mExcludeSuffix;
    private JTextField mHaEPluginPath;
    private JTextField mQpsLimit;
    private OnTabEventListener mOnTabEventListener;

    @Override
    protected void initView() {
        addConfigItem("QPS", "Set http request QPS limit", newQpsPanel());
        addConfigItem("Web name collect", "Select a file path", newWebNameCollectPanel());
        addConfigItem("Json field collect", "Select a directory path", newJsonFieldCollectPanel());
        addConfigItem("Exclude suffix", "Proxy message suffix filter", newExcludeSuffixPanel());
        addConfigItem("HaE", "Set HaE plugin file path", newHaEPluginPathPanel());
    }

    @Override
    public String getTitleName() {
        return "Other";
    }

    private JPanel newQpsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));

        mQpsLimit = new JTextField(Config.get(Config.KEY_QPS_LIMIT), 20);
        mQpsLimit.addKeyListener(new NumberFilter());
        panel.add(mQpsLimit);

        JButton button = new JButton("Save");
        button.setActionCommand("save-qps-limit");
        button.addActionListener(this);
        panel.add(button);
        return panel;
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

    private JPanel newExcludeSuffixPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(3));

        mExcludeSuffix = new JTextField(getExcludeSuffix(), 50);
        panel.add(mExcludeSuffix);

        JButton button = new JButton("Save");
        button.setActionCommand("save-exclude-suffix");
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
            case "save-qps-limit":
                String limitText = mQpsLimit.getText();
                if (StringUtils.isEmpty(limitText) || limitText.length() > 4) {
                    UIHelper.showTipsDialog("QPS limit value invalid");
                    return;
                }
                Config.put(Config.KEY_QPS_LIMIT, limitText);
                UIHelper.showTipsDialog("Save success!");
                if (mOnTabEventListener != null) {
                    mOnTabEventListener.onTabEventMethod(EVENT_QPS_LIMIT, limitText);
                }
                break;
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
            case "save-exclude-suffix":
                String oldExcludeSuffix = getExcludeSuffix();
                String excludeSuffix = mExcludeSuffix.getText();
                if (oldExcludeSuffix.equals(excludeSuffix)) {
                    return;
                }
                Config.put(Config.KEY_EXCLUDE_SUFFIX, excludeSuffix);
                UIHelper.showTipsDialog("Save success!");
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

    private String getExcludeSuffix() {
        return Config.get(Config.KEY_EXCLUDE_SUFFIX);
    }

    private String getHaEPluginPath() {
        String path = Config.get(Config.KEY_HAE_PLUGIN_PATH);
        if (StringUtils.isEmpty(path)) {
            return "";
        }
        return path;
    }

    public void setOnTabEventListener(OnTabEventListener l) {
        this.mOnTabEventListener = l;
    }
}
