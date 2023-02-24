package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.Config;

/**
 * Host设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class HostTab extends BaseConfigTab {

    @Override
    protected void initView() {
        // Host白名单配置
        addWordListPanel("Host Whitelist", "Host Whitelist options", Config.KEY_WHITE_LIST);
        // Host黑名单配置
        addWordListPanel("Host Blacklist", "Host Blacklist options", Config.KEY_BLACK_LIST);
    }

    @Override
    public String getTitleName() {
        return "Host";
    }
}
