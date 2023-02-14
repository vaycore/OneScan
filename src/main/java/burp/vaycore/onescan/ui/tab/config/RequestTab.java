package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.OnDataChangeListener;
import burp.vaycore.onescan.ui.widget.SimpleWordlist;

import javax.swing.*;
import java.util.ArrayList;

/**
 * Request设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class RequestTab extends BaseConfigTab implements OnDataChangeListener {

    private SimpleWordlist mHeaderListView;
    private SimpleWordlist mUAList;

    @Override
    protected void initView() {
        // 请求头配置
        mHeaderListView = new SimpleWordlist(Config.getList(Config.KEY_HEADER_LIST));
        mHeaderListView.setOnDataChangeListener(this);
        mHeaderListView.setActionCommand("header-list-view");
        addConfigItem("Header", "Request header options", mHeaderListView);
        // 请求头配置
        mUAList = new SimpleWordlist(Config.getList(Config.KEY_UA_LIST));
        mUAList.setOnDataChangeListener(this);
        mUAList.setActionCommand("user-agent-list-view");
        addConfigItem("UserAgent", "Set {{random.ua}} list options", mUAList);
    }

    @Override
    public String getTitleName() {
        return "Request";
    }

    @Override
    public void onDataChange(String action) {
        ArrayList<String> listData;
        switch (action) {
            case "header-list-view":
                listData = mHeaderListView.getListData();
                Config.putList(Config.KEY_HEADER_LIST, listData);
                break;
            case "user-agent-list-view":
                listData = mUAList.getListData();
                Config.putList(Config.KEY_UA_LIST, listData);
                break;
            default:
                break;
        }
    }
}
