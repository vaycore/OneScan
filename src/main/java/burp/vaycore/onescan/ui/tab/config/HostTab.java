package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.base.BaseConfigTab;

/**
 * Host设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class HostTab extends BaseConfigTab {

    @Override
    protected void initView() {
        // Host白名单配置
        addWordListPanel("Host Whitelist", "Host Whitelist options", WordlistManager.KEY_WHITE_HOST);
        // Host黑名单配置
        addWordListPanel("Host Blacklist", "Host Blacklist options", WordlistManager.KEY_BLACK_HOST);
    }

    @Override
    public String getTitleName() {
        return "Host";
    }
}
