package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.OnDataChangeListener;
import burp.vaycore.onescan.ui.base.BaseConfigTab;
import burp.vaycore.onescan.ui.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.payloadlist.SimplePayloadList;

import java.util.ArrayList;

/**
 * Payload设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class PayloadTab extends BaseConfigTab implements OnDataChangeListener {

    private SimplePayloadList mProcessList;

    @Override
    protected void initView() {
        // payload 列表配置
        addWordListPanel("Payload", "Set payload list", Config.KEY_PAYLOAD_LIST);

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
        if ("payload-process-list-view".equals(action)) {
            ArrayList<PayloadItem> list = mProcessList.getDataList();
            Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, list);
        }
    }
}
