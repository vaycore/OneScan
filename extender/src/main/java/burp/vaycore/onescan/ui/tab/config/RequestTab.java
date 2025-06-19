package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;
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

    /**
     * request delay 变量值变更事件
     */
    public static final String EVENT_REQUEST_DELAY = "event-request-delay";

    @Override
    protected void initView() {
        // QPS限制器配置
        addTextConfigPanel(L.get("qps"), L.get("qps_sub_title"),
                20, Config.KEY_QPS_LIMIT).addKeyListener(new NumberFilter(4));
        // 请求延时配置
        addTextConfigPanel(L.get("request_delay"), L.get("request_delay_sub_title"),
                20, Config.KEY_REQUEST_DELAY).addKeyListener(new NumberFilter(5));
        // 控制递归层数
        addScanLevelConfigPanel();
        // 请求重试配置
        addTextConfigPanel(L.get("request_retry"), L.get("request_retry_sub_title"),
                20, Config.KEY_RETRY_COUNT).addKeyListener(new NumberFilter(1));
        // 重试间隔时间配置
        addTextConfigPanel(L.get("request_retry_interval"), L.get("request_retry_interval_sub_title"),
                20, Config.KEY_RETRY_INTERVAL).addKeyListener(new NumberFilter(5));
        // 过滤请求方法
        addTextConfigPanel(L.get("include_method"), L.get("include_method_sub_title"), 20, Config.KEY_INCLUDE_METHOD);
        // 根据后缀过滤请求包
        addTextConfigPanel(L.get("exclude_suffix"), L.get("exclude_suffix_sub_title"), 50, Config.KEY_EXCLUDE_SUFFIX);
        // 请求头配置
        addWordListPanel(L.get("header"), L.get("header_sub_title"), WordlistManager.KEY_HEADERS);
        // 移除请求头配置
        addWordListPanel(L.get("remove_header"), L.get("remove_header_sub_title"), WordlistManager.KEY_REMOVE_HEADERS);
        // 请求头UserAgent配置
        addWordListPanel(L.get("user_agent"), L.get("user_agent_sub_title"), WordlistManager.KEY_USER_AGENT);
    }

    protected void addScanLevelConfigPanel() {
        String configKey = Config.KEY_SCAN_LEVEL;
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        // 单选按钮布局
        JPanel radioPanel = new JPanel(new HLayout(10));
        JRadioButton left = new JRadioButton(L.get("left_to_right"));
        left.setSelected(Config.DIRECT_LEFT.equals(direct));
        radioPanel.add(left);
        JRadioButton right = new JRadioButton(L.get("right_to_left"));
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
        JButton button = new JButton(L.get("save"));
        button.addActionListener(e -> {
            boolean state = onTextConfigSave(configKey, textField.getText());
            if (state) {
                UIHelper.showTipsDialog(L.get("save_success"));
            }
        });
        textFieldPanel.add(button);
        addConfigItem(L.get("scan_level"), L.get("scan_level_sub_title"), radioPanel, textFieldPanel);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.request");
    }

    @Override
    protected boolean onTextConfigSave(String configKey, String text) {
        int value = StringUtils.parseInt(text, -1);
        if (Config.KEY_QPS_LIMIT.equals(configKey)) {
            if (value < 1 || value > 9999) {
                UIHelper.showTipsDialog(L.get("qps_limit_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
            Config.put(configKey, text);
            sendTabEvent(EVENT_QPS_LIMIT, text);
            return true;
        } else if (Config.KEY_REQUEST_DELAY.equals(configKey)) {
            if (value < 0 || value > 99999) {
                UIHelper.showTipsDialog(L.get("request_delay_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
            Config.put(configKey, text);
            sendTabEvent(EVENT_REQUEST_DELAY, text);
            return true;
        } else if (Config.KEY_SCAN_LEVEL.equals(configKey)) {
            if (value < 1 || value > 99) {
                UIHelper.showTipsDialog(L.get("scan_level_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
        } else if (Config.KEY_RETRY_COUNT.equals(configKey)) {
            if (value < 0 || value > 9) {
                UIHelper.showTipsDialog(L.get("request_retry_count_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
        } else if (Config.KEY_RETRY_INTERVAL.equals(configKey)) {
            if (value < 0 || value > 99999) {
                UIHelper.showTipsDialog(L.get("request_retry_interval_value_invalid"));
                return false;
            }
            text = String.valueOf(value);
        }
        return super.onTextConfigSave(configKey, text);
    }
}
