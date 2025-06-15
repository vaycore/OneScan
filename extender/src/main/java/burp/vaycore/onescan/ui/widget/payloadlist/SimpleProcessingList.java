package burp.vaycore.onescan.ui.widget.payloadlist;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.OnDataChangeListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

/**
 * 简单 Payload Processing 列表
 * <p>
 * Created by vaycore on 2023-11-07.
 */
public class SimpleProcessingList extends JPanel implements ActionListener {

    private final ProcessingListModel mListModel;
    private JTable mListView;
    private String mAction;
    private OnDataChangeListener mOnDataChangeListener;

    public SimpleProcessingList(ArrayList<ProcessingItem> list) {
        mListModel = new ProcessingListModel();
        mListModel.addTableModelListener(e -> dataChanged());
        initData(list);
        initView();
    }

    public void setActionCommand(String action) {
        this.mAction = action;
    }

    public String getActionCommand() {
        if (StringUtils.isEmpty(this.mAction)) {
            return toString();
        }
        return this.mAction;
    }

    private void initData(ArrayList<ProcessingItem> list) {
        setListData(list);
    }

    /**
     * 设置列表数据
     *
     * @param list 数据列表
     */
    public void setListData(ArrayList<ProcessingItem> list) {
        if (list == null) {
            return;
        }
        mListModel.clearAll();
        for (ProcessingItem item : list) {
            mListModel.add(item);
        }
    }

    /**
     * 获取列表数据
     *
     * @return 列表数据
     */
    public ArrayList<ProcessingItem> getDataList() {
        return mListModel.getDataList(false);
    }

    /**
     * 添加数据监听器
     *
     * @param l 监听器
     */
    public void setOnDataChangeListener(OnDataChangeListener l) {
        this.mOnDataChangeListener = l;
    }

    private void initView() {
        setLayout(new HLayout(5));
        setPreferredSize(new Dimension(0, 200));

        add(newLeftPanel(this), "85px");
        add(newRightPanel(), "460px");
    }

    static JPanel newLeftPanel(ActionListener l) {
        JPanel panel = new JPanel(new VLayout(3));
        panel.add(newLeftPanelButton(L.get("add"), "add-item", l));
        panel.add(newLeftPanelButton(L.get("edit"), "edit-item", l));
        panel.add(newLeftPanelButton(L.get("remove"), "remove-item", l));
        panel.add(newLeftPanelButton(L.get("clear"), "clear-item", l));
        panel.add(newLeftPanelButton(L.get("up"), "up-item", l));
        panel.add(newLeftPanelButton(L.get("down"), "down-item", l));
        return panel;
    }

    static JButton newLeftPanelButton(String text, String action, ActionListener l) {
        JButton button = new JButton(text);
        button.setActionCommand(action);
        button.addActionListener(l);
        return button;
    }

    private JPanel newRightPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new VLayout());

        mListView = new JTable(mListModel);
        UIHelper.setTableHeaderAlign(mListView, SwingConstants.CENTER);
        mListView.getColumnModel().getColumn(0).setMinWidth(65);
        mListView.getColumnModel().getColumn(0).setMaxWidth(65);
        mListView.getColumnModel().getColumn(1).setMinWidth(65);
        mListView.getColumnModel().getColumn(1).setMaxWidth(65);
        mListView.getColumnModel().getColumn(3).setMinWidth(75);
        mListView.getColumnModel().getColumn(3).setMaxWidth(75);
        mListView.getTableHeader().setReorderingAllowed(false);
        JScrollPane scrollPane = new JScrollPane(mListView);
        panel.add(scrollPane, "1w");
        return panel;
    }

    /**
     * 获取选中的真实数据下标
     *
     * @return 未选中返回-1
     */
    private int getSelectedRowIndex() {
        int rowIndex = mListView.getSelectedRow();
        if (rowIndex < 0 || rowIndex >= mListView.getRowCount()) {
            return -1;
        }
        return mListView.convertRowIndexToModel(rowIndex);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        switch (action) {
            case "add-item":
                ProcessingItem newItem = showItemOptionPane(null);
                mListModel.add(newItem);
                break;
            case "clear-item":
                int state = UIHelper.showOkCancelDialog(L.get("confirm_clear_the_list_hint"));
                if (state == JOptionPane.OK_OPTION) {
                    mListModel.clearAll();
                }
                break;
        }
        int index = getSelectedRowIndex();
        if (index < 0) {
            return;
        }
        switch (action) {
            case "edit-item":
                ProcessingItem item = mListModel.get(index);
                item = showItemOptionPane(item);
                mListModel.set(index, item);
                break;
            case "remove-item":
                String name = mListModel.get(index).getName();
                // 防止误删除，删除前先提示
                int state = UIHelper.showOkCancelDialog(L.get("confirm_remove_processing_rule_hint", name));
                if (state != JOptionPane.OK_OPTION) {
                    return;
                }
                mListModel.remove(index);
                if (index > 0) {
                    mListView.changeSelection(--index, 0, false, false);
                } else {
                    mListView.changeSelection(0, 0, false, false);
                }
                break;
            case "up-item":
                int upIndex = index - 1;
                if (upIndex >= 0) {
                    ProcessingItem temp = mListModel.get(upIndex);
                    mListModel.set(upIndex, mListModel.get(index));
                    mListModel.set(index, temp);
                    mListView.changeSelection(upIndex, 0, false, false);
                }
                break;
            case "down-item":
                int downIndex = index + 1;
                if (downIndex < mListModel.size()) {
                    ProcessingItem temp = mListModel.get(index);
                    mListModel.set(index, mListModel.get(downIndex));
                    mListModel.set(downIndex, temp);
                    mListView.changeSelection(downIndex, 0, false, false);
                }
                break;
            default:
                break;
        }
    }

    private ProcessingItem showItemOptionPane(ProcessingItem item) {
        boolean hasCreate = item == null;
        return showItemOptionPane(hasCreate, item);
    }

    private ProcessingItem showItemOptionPane(boolean hasCreate, ProcessingItem item) {
        String title = L.get("add_payload_processing_title");
        if (!hasCreate) {
            title = L.get("edit_payload_processing_title");
        }
        // 布局
        JPanel panel = new JPanel(new VLayout(5));
        panel.setPreferredSize(new Dimension(490, 260));
        // 规则名
        JPanel namePanel = new JPanel(new HLayout(5, true));
        namePanel.add(new JLabel(L.get("rule_name_label")));
        JTextField nameUI = new JTextField();
        namePanel.add(nameUI, "1w");
        panel.add(namePanel);
        // 合并到请求
        JCheckBox mergeUI = new JCheckBox(L.get("merge_to_request"));
        panel.add(mergeUI);
        panel.add(new JPanel(), "5px");
        // 规则表UI
        SimplePayloadList listUI = new SimplePayloadList();
        panel.add(listUI);
        // 数据填充
        if (item != null) {
            nameUI.setText(item.getName());
            mergeUI.setSelected(item.isMerge());
            listUI.setListData(item.getItems());
        }
        // 显示对话框
        int ret = UIHelper.showCustomDialog(title, panel);
        if (ret != JOptionPane.OK_OPTION) {
            return null;
        }
        // 赋值 ProcessingItem 实例
        if (item == null) {
            item = new ProcessingItem();
            item.setEnabled(true);
        }
        // 参数提醒
        StringBuilder errorTips = new StringBuilder();
        // 检测 name 参数
        String name = nameUI.getText();
        if (StringUtils.isEmpty(name)) {
            errorTips.append(L.get("rule_name_is_empty_hint")).append("\n");
        } else {
            item.setName(name);
        }
        // 参数 merge 直接赋值
        boolean merge = mergeUI.isSelected();
        item.setMerge(merge);
        // 检测 Rule list 参数
        ArrayList<PayloadItem> payloadItems = listUI.getDataList();
        if (payloadItems.isEmpty()) {
            errorTips.append(L.get("payload_rule_list_is_empty_hint"));
        } else {
            item.setItems(payloadItems);
        }
        if (StringUtils.isNotEmpty(errorTips)) {
            UIHelper.showTipsDialog(errorTips.toString());
            return showItemOptionPane(hasCreate, item);
        }
        return item;
    }

    /**
     * 列表数据有修改
     */
    private void dataChanged() {
        if (mOnDataChangeListener != null) {
            mOnDataChangeListener.onDataChange(getActionCommand());
        }
    }
}
