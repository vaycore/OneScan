package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.NumberFilter;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.base.BaseConfigTab;

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
                20, Config.KEY_QPS_LIMIT).addKeyListener(new NumberFilter());
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

    @Override
    public String getTitleName() {
        return "Request";
    }

    @Override
    protected boolean onTextConfigSave(String configKey, String text) {
        if (Config.KEY_QPS_LIMIT.equals(configKey)) {
            if (StringUtils.isEmpty(text) || text.length() > 4) {
                UIHelper.showTipsDialog("QPS limit value invalid");
                return false;
            }
            Config.put(configKey, text);
            sendTabEvent(EVENT_QPS_LIMIT, text);
            return true;
        }
        return super.onTextConfigSave(configKey, text);
    }
}
