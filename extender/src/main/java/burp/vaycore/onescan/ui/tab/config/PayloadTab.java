package burp.vaycore.onescan.ui.tab.config;

import burp.vaycore.onescan.common.Config;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.OnDataChangeListener;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.base.BaseConfigTab;
import burp.vaycore.onescan.ui.widget.payloadlist.ProcessingItem;
import burp.vaycore.onescan.ui.widget.payloadlist.SimpleProcessingList;

import java.util.ArrayList;

/**
 * Payload设置
 * <p>
 * Created by vaycore on 2022-08-20.
 */
public class PayloadTab extends BaseConfigTab implements OnDataChangeListener {

    private SimpleProcessingList mProcessList;

    @Override
    protected void initView() {
        // payload 列表配置
        addWordListPanel(L.get("payload"), L.get("payload_sub_title"), WordlistManager.KEY_PAYLOAD);

        // payload process 列表配置
        mProcessList = new SimpleProcessingList(Config.getPayloadProcessList());
        mProcessList.setActionCommand("payload-process-list-view");
        mProcessList.setOnDataChangeListener(this);
        addConfigItem(L.get("payload_processing"), L.get("payload_processing_sub_title"), mProcessList);
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.payload");
    }

    @Override
    public void onDataChange(String action) {
        if ("payload-process-list-view".equals(action)) {
            ArrayList<ProcessingItem> list = mProcessList.getDataList();
            Config.put(Config.KEY_PAYLOAD_PROCESS_LIST, list);
        }
    }
}
