package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.NumberFilter;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.base.BaseConfigTab;

import javax.swing.*;
import java.awt.event.ItemEvent;

/**
 * Request设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class RequestTab extends BaseConfigTab {

    /**
     * limit 变量值变更事件
     */
    public static final String EVENT_QPS_LIMIT = "event-qps-limit";

    @Override
    protected void initView() {
        // QPS限制器配置
        addTextConfigPanel("QPS", "Set http request QPS limit",
                20, Config.KEY_QPS_LIMIT).addKeyListener(new NumberFilter(4));
        // 控制递归层数
        addScanLevelConfigPanel();
        // 请求重试配置
        addTextConfigPanel("Retry", "Set http retry count",
                20, Config.KEY_RETRY_COUNT).addKeyListener(new NumberFilter(1));
        // 过滤请求方法
        addTextConfigPanel("Include method", "Set request method whitelist", 20, Config.KEY_INCLUDE_METHOD);
        // 根据后缀过滤请求包
        addTextConfigPanel("Exclude suffix", "Proxy message suffix filter", 50, Config.KEY_EXCLUDE_SUFFIX);
        // 请求头配置
        addWordListPanel("Header", "Request header options", WordlistManager.KEY_HEADERS);
        // 排除请求头配置
        addWordListPanel("Exclude header", "Exclude request header by key", WordlistManager.KEY_EXCLUDE_HEADERS);
        // 请求头UserAgent配置
        addWordListPanel("UserAgent", "Set {{random.ua}} list options", WordlistManager.KEY_USER_AGENT);
    }

    protected void addScanLevelConfigPanel() {
        String configKey = Config.KEY_SCAN_LEVEL;
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        // 单选按钮布局
        JPanel radioPanel = new JPanel(new HLayout(10));
        JRadioButton left = new JRadioButton("Left to right");
        left.setSelected(Config.DIRECT_LEFT.equals(direct));
        radioPanel.add(left);
        JRadioButton right = new JRadioButton("Right to left");
        right.setSelected(!Config.DIRECT_LEFT.equals(direct));
        radioPanel.add(right);
        UIHelper.createRadioGroup(left, right);
        // 选项变更，保存配置
        left.addItemListener(e -> {
            int state = e.getStateChange();
            String newDirect = state == ItemEvent.SELECTED ? Config.DIRECT_LEFT : Config.DIRECT_RIGHT;
            Config.put(Config.KEY_SCAN_LEVEL_DIRECT, newDirect);
        });
        // 输入框布局
        JPanel textFieldPanel = new JPanel(new HLayout(3));
        JTextField textField = new JTextField(Config.get(configKey), 20);
        textField.addKeyListener(new NumberFilter(2));
        textFieldPanel.add(textField);
        JButton button = new JButton("Save");
        button.addActionListener(e -> {
            boolean state = onTextConfigSave(configKey, textField.getText());
            if (state) {
                UIHelper.showTipsDialog("Save success!");
            }
        });
        textFieldPanel.add(button);
        addConfigItem("Scan level", "Set directory scan level", radioPanel, textFieldPanel);
    }

    @Override
    public String getTitleName() {
        return "Request";
    }

    @Override
    protected boolean onTextConfigSave(String configKey, String text) {
        if (Config.KEY_QPS_LIMIT.equals(configKey)) {
            int value = StringUtils.parseInt(text, -1);
            if (value < 1 || value > 9999) {
                UIHelper.showTipsDialog("QPS limit value invalid.(range: 1-9999)");
                return false;
            }
            Config.put(configKey, text);
            sendTabEvent(EVENT_QPS_LIMIT, text);
            return true;
        } else if (Config.KEY_SCAN_LEVEL.equals(configKey)) {
            int value = StringUtils.parseInt(text, -1);
            if (value < 1 || value > 99) {
                UIHelper.showTipsDialog("Scan Level value invalid.(range: 1-99)");
                return false;
            }
        } else if (Config.KEY_RETRY_COUNT.equals(configKey)) {
            int value = StringUtils.parseInt(text, -1);
            if (value < 0 || value > 9) {
                UIHelper.showTipsDialog("Retry count value invalid.(range: 0-9)");
                return false;
            }
        }
        return super.onTextConfigSave(configKey, text);
    }
}
