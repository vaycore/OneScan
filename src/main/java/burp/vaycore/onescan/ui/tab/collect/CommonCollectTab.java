package burp.vaycore.onescan.ui.tab.collect;

import burp.vaycore.onescan.bean.CollectData;
import burp.vaycore.onescan.bean.CollectNode;
import burp.vaycore.onescan.manager.CollectManager;
import burp.vaycore.onescan.ui.base.BaseCollectTab;
import burp.vaycore.onescan.ui.widget.CollectTable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 通用收集数据展示 Tab
 * <p>
 * Created by vaycore on 2023-12-22.
 */
public class CommonCollectTab extends BaseCollectTab<String> {

    private final String mName;
    private CollectTable.CollectTableModel<String> mTableModel;

    public CommonCollectTab(String name) {
        this.mName = name;
    }

    @Override
    protected CollectTable.CollectTableModel<String> buildTableModel() {
        mTableModel = new CollectTable.CollectTableModel<String>() {
            @Override
            protected String[] buildColumnNames() {
                return new String[]{"Info"};
            }

            @Override
            protected Object buildItemValue(String data, int columnIndex) {
                return data;
            }
        };
        return mTableModel;
    }

    @Override
    public void setupPath(String path) {
        CollectNode node = CollectManager.getNodeByPath(path);
        if (node == null) {
            mTableModel.clearAll();
            return;
        }
        ArrayList<CollectData<String>> list = new ArrayList<>();
        loadData(node, list);
        mTableModel.setList(list);
    }

    @Override
    public int getDataCount() {
        if (mTableModel == null) {
            return 0;
        }
        return mTableModel.getRowCount();
    }

    private void loadData(CollectNode node, ArrayList<CollectData<String>> list) {
        String name = getTitleName();
        Set<String> dataSet = node.getData(name);
        for (String dataItem: dataSet) {
            int id = list.size();
            list.add(new CollectData<>(id, node.getName(), dataItem));
        }
        if (node.isNodesEmpty()) {
            return;
        }
        List<CollectNode> nodes = node.getNodes();
        for (CollectNode nodeItem : nodes) {
            loadData(nodeItem, list);
        }
    }

    @Override
    public String getTitleName() {
        return this.mName;
    }
}
