package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.OnDataChangeListener;
import burp.vaycore.onescan.ui.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.payloadlist.SimplePayloadList;
import burp.vaycore.onescan.ui.widget.SimpleWordlist;

import java.util.ArrayList;

/**
 * Payload设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class PayloadTab extends BaseConfigTab implements OnDataChangeListener {

    private SimpleWordlist mPayloadList;
    private SimplePayloadList mProcessList;

    @Override
    protected void initView() {
        // payload 列表配置
        mPayloadList = new SimpleWordlist(Config.getList(Config.KEY_PAYLOAD_LIST));
        mPayloadList.setActionCommand("payload-list-view");
        mPayloadList.setOnDataChangeListener(this);
        addConfigItem("Payload", "Set payload list", mPayloadList);

        // payload process 列表配置
        mProcessList = new SimplePayloadList(Config.getPayloadProcessList());
        mProcessList.setActionCommand("payload-process-list-view");
        mProcessList.setOnDataChangeListener(this);
        addConfigItem("Payload Processing", "Set payload processing list", mProcessList);
    }

    @Override
    public String getTitleName() {
        return "Payload";
    }

    @Override
    public void onDataChange(String action) {
        ArrayList<String> listData;
        switch (action) {
            case "payload-list-view":
                listData = mPayloadList.getListData();
                Config.putList(Config.KEY_PAYLOAD_LIST, listData);
                break;
            case "payload-process-list-view":
                ArrayList<PayloadItem> list = mProcessList.getDataList();
                Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, list);
                break;
            default:
                break;
        }
    }
}
