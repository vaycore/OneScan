package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.OnDataChangeListener;
import burp.vaycore.onescan.ui.widget.SimpleWordlist;

import java.util.ArrayList;

/**
 * Host设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class HostTab extends BaseConfigTab implements OnDataChangeListener {

    private SimpleWordlist mHostWhitelist;
    private SimpleWordlist mHostBlacklist;

    @Override
    protected void initView() {
        // Host白名单配置
        mHostWhitelist = new SimpleWordlist(Config.getList(Config.KEY_WHITE_LIST));
        mHostWhitelist.setOnDataChangeListener(this);
        mHostWhitelist.setActionCommand("host-whitelist-view");
        addConfigItem("Host Whitelist", "Host Whitelist options", mHostWhitelist);
        // Host黑名单配置
        mHostBlacklist = new SimpleWordlist(Config.getList(Config.KEY_BLACK_LIST));
        mHostBlacklist.setOnDataChangeListener(this);
        mHostBlacklist.setActionCommand("host-blacklist-view");
        addConfigItem("Host Blacklist", "Host Blacklist options", mHostBlacklist);
    }

    @Override
    public String getTitleName() {
        return "Host";
    }

    @Override
    public void onDataChange(String action) {
        ArrayList<String> listData;
        switch (action) {
            case "host-whitelist-view":
                listData = mHostWhitelist.getListData();
                Config.putList(Config.KEY_WHITE_LIST, listData);
                break;
            case "host-blacklist-view":
                listData = mHostBlacklist.getListData();
                Config.putList(Config.KEY_BLACK_LIST, listData);
                break;
            default:
                break;
        }
    }
}
