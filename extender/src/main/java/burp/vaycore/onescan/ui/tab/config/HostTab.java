package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.L;
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
        addWordListPanel(L.get("host_allowlist"), L.get("host_allowlist_sub_title"), WordlistManager.KEY_HOST_ALLOWLIST);
        // Host黑名单配置
        addWordListPanel(L.get("host_blocklist"), L.get("host_blocklist_sub_title"), WordlistManager.KEY_HOST_BLOCKLIST);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.host");
    }
}
