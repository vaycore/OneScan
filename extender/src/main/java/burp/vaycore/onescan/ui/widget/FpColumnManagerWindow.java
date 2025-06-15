package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.FpColumn;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * 指纹字段管理窗口
 * <p>
 * Created by vaycore on 2025-05-20.
 */
public class FpColumnManagerWindow extends JPanel implements ActionListener {

    private JFrame mFrame;
    private ColumnTableModel mTableModel;
    private JTable mColumnTable;

    public FpColumnManagerWindow() {
        super(new VLayout(0));
        setBorder(new EmptyBorder(5, 5, 5, 5));
        initView();
        initData();
    }

    private void initView() {
        initContentPanel();
        initBottomPanel();
    }

    private void initContentPanel() {
        JPanel panel = new JPanel(new HLayout(5));
        // 左边按钮布局
        panel.add(createButtonPanel(), "75px");
        // 右边指纹字段表格布局
        mTableModel = new ColumnTableModel();
        mColumnTable = createColumnTablePanel(mTableModel);
        JScrollPane scrollPane = new JScrollPane(mColumnTable);
        panel.add(scrollPane, "1w");
        add(panel, "1w");
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new VLayout(5));
        panel.add(createRulesLeftButton(L.get("add"), "add-item"));
        panel.add(createRulesLeftButton(L.get("edit"), "edit-item"));
        panel.add(createRulesLeftButton(L.get("delete"), "delete-item"));
        panel.add(createRulesLeftButton(L.get("up"), "up-item"));
        panel.add(createRulesLeftButton(L.get("down"), "down-item"));
        return panel;
    }

    private JButton createRulesLeftButton(String text, String action) {
        JButton btn = new JButton(text);
        btn.setActionCommand(action);
        btn.addActionListener(this);
        return btn;
    }

    private JTable createColumnTablePanel(ColumnTableModel model) {
        JTable table = new JTable(model);
        UIHelper.setTableHeaderAlign(table, SwingConstants.CENTER);
        table.getTableHeader().setReorderingAllowed(false);
        // 设置列宽
        table.getColumnModel().getColumn(0).setMinWidth(70);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        return table;
    }

    private void initBottomPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        panel.add(new JPanel(), "1w");
        // 关闭窗口
        JButton closeBtn = new JButton(L.get("close"));
        closeBtn.setActionCommand("close");
        closeBtn.addActionListener(this);
        panel.add(closeBtn);
        // 添加到主布局
        add(panel);
    }

    private void initData() {
        List<FpColumn> columns = FpManager.getColumns();
        mTableModel.setList(columns);
    }

    /**
     * 获取选中的真实数据下标
     *
     * @return 未选中返回-1
     */
    private int getSelectedRowIndex() {
        int rowIndex = mColumnTable.getSelectedRow();
        if (rowIndex < 0 || rowIndex >= mColumnTable.getRowCount()) {
            return -1;
        }
        return mColumnTable.convertRowIndexToModel(rowIndex);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        int rowIndex = getSelectedRowIndex();
        switch (e.getActionCommand()) {
            case "add-item":
                doAddItem();
                break;
            case "edit-item":
                doEditItem(rowIndex);
                break;
            case "delete-item":
                doDeleteItem(rowIndex);
                break;
            case "up-item":
                doUpItem(rowIndex);
                break;
            case "down-item":
                doDownItem(rowIndex);
                break;
            case "close":
                closeWindow();
                break;
            default:
                break;
        }
    }

    /**
     * 添加
     */
    private void doAddItem() {
        FpColumn column = showFpColumnDetailDialog();
        if (column == null) {
            return;
        }
        mTableModel.add(column);
    }

    /**
     * 编辑
     */
    private void doEditItem(int index) {
        if (index < 0 || index >= mTableModel.getRowCount()) {
            return;
        }
        FpColumn column = mTableModel.get(index);
        column = showFpColumnDetailDialog(false, column);
        if (column == null) {
            return;
        }
        mTableModel.set(index, column);
    }

    /**
     * 删除
     */
    private void doDeleteItem(int index) {
        if (index < 0 || index >= mTableModel.getRowCount()) {
            return;
        }
        FpColumn column = mTableModel.get(index);
        if (column == null) {
            return;
        }
        String message = L.get("fingerprint_column_manager.delete_column_hint", column.getName());
        int ret = UIHelper.showOkCancelDialog(message, this);
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }
        mTableModel.remove(index);
        if (index > 0) {
            mColumnTable.changeSelection(--index, 0, false, false);
        } else {
            mColumnTable.changeSelection(0, 0, false, false);
        }
    }

    /**
     * 上移
     */
    private void doUpItem(int index) {
        if (index < 0 || index >= mTableModel.getRowCount()) {
            return;
        }
        int upIndex = index - 1;
        if (upIndex >= 0) {
            doMoveItem(index, upIndex);
        }
    }

    /**
     * 下移
     */
    private void doDownItem(int index) {
        if (index < 0 || index >= mTableModel.getRowCount()) {
            return;
        }
        int downIndex = index + 1;
        if (downIndex < mColumnTable.getRowCount()) {
            doMoveItem(index, downIndex);
        }
    }

    /**
     * 移动 Item 位置
     *
     * @param index   当前位置下标
     * @param toIndex 目标位置下标
     */
    private void doMoveItem(int index, int toIndex) {
        FpColumn temp = mTableModel.get(index);
        mTableModel.set(index, mTableModel.get(toIndex));
        mTableModel.set(toIndex, temp);
        mColumnTable.changeSelection(toIndex, 0, false, false);
    }

    /**
     * 显示窗口
     */
    public void showWindow() {
        if (mFrame != null) {
            if (isShowing()) {
                mFrame.toFront();
            } else {
                initData();
                mFrame.setVisible(true);
            }
            return;
        }
        mFrame = new JFrame(L.get("fingerprint_column_manager.title"));
        // 窗口大小
        mFrame.setSize(360, 420);
        // 设置布局内容
        mFrame.setContentPane(this);
        // 其它设置
        mFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        mFrame.setLocationRelativeTo(UIHelper.getMainFrame());
        mFrame.setResizable(false);
        mFrame.setVisible(true);
    }

    /**
     * 关闭窗口
     */
    public void closeWindow() {
        if (mFrame != null && isShowing()) {
            mFrame.dispose();
        }
    }

    /**
     * 显示指纹字段详情对话框
     *
     * @return 用户取消返回null
     */
    private FpColumn showFpColumnDetailDialog() {
        return showFpColumnDetailDialog(true, FpManager.generateFpColumn());
    }

    /**
     * 显示指纹字段详情对话框
     *
     * @param column 指纹字段实例
     * @return 用户取消返回null
     */
    private FpColumn showFpColumnDetailDialog(boolean hasCreate, FpColumn column) {
        String title;
        if (hasCreate) {
            title = L.get("fingerprint_column_manager.add_column");
        } else {
            title = L.get("fingerprint_column_manager.edit_column");
        }
        JPanel panel = createFpColumnDetailPanel(column);
        int ret = UIHelper.showCustomDialog(title, panel, this);
        if (ret != JOptionPane.OK_OPTION) {
            return null;
        }
        // 获取输入的内容
        JTextField textField = (JTextField) panel.getComponent(1);
        String columnName = textField.getText();
        column.setName(columnName);
        // 检测输入的字段名是否有效
        if (StringUtils.isEmpty(columnName) || columnName.length() > 20) {
            String message = L.get("fingerprint_column_manager.column_name_invalid");
            UIHelper.showTipsDialog(message, this);
            return showFpColumnDetailDialog(hasCreate, column);
        }
        return column;
    }

    /**
     * 创建指纹字段详情布局
     *
     * @param column 指纹字段实例
     * @return 布局实例
     */
    private JPanel createFpColumnDetailPanel(FpColumn column) {
        JPanel panel = new JPanel(new VLayout(8, false));
        panel.setBorder(new EmptyBorder(0, 0, 0, 0));
        panel.setPreferredSize(new Dimension(300, 60));
        // 标签
        String labelText = L.get("fingerprint_column_manager.table_columns.name") + "：";
        JLabel label = new JLabel(labelText);
        label.setBorder(new EmptyBorder(0, 3, 0, 0));
        panel.add(label);
        // 输入框
        JTextField field = new JTextField(column.getName());
        panel.add(field);
        return panel;
    }

    private static class ColumnTableModel extends AbstractTableModel {

        private static final String[] COLUMN_NAMES = {
                L.get("fingerprint_column_manager.table_columns.id"),
                L.get("fingerprint_column_manager.table_columns.name"),
        };
        private final List<FpColumn> mList = new ArrayList<>();

        public void add(FpColumn column) {
            if (column != null) {
                synchronized (mList) {
                    int id = getRowCount();
                    mList.add(column);
                    FpManager.addColumnsItem(column);
                    fireTableRowsInserted(id, id);
                }
            }
        }

        public void remove(int index) {
            synchronized (mList) {
                if (index >= 0 && index < getRowCount()) {
                    mList.remove(index);
                    FpManager.removeColumnsItem(index);
                    fireTableRowsDeleted(index, index);
                }
            }
        }

        public void set(int index, FpColumn column) {
            if (column == null) {
                return;
            }
            synchronized (mList) {
                if (index >= 0 && index < getRowCount()) {
                    mList.set(index, column);
                    FpManager.setColumnsItem(index, column);
                    this.fireTableRowsUpdated(index, index);
                }
            }
        }

        public FpColumn get(int index) {
            synchronized (mList) {
                if (index >= 0 && index < getRowCount()) {
                    return mList.get(index);
                }
                return null;
            }
        }

        public void setList(List<FpColumn> list) {
            if (list == null) {
                return;
            }
            synchronized (mList) {
                mList.clear();
                if (!list.isEmpty()) {
                    mList.addAll(list);
                }
                this.fireTableDataChanged();
            }
        }

        @Override
        public int getRowCount() {
            return mList.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            FpColumn column = mList.get(rowIndex);
            if (columnIndex == 0) {
                return column.getId();
            } else {
                return column.getName();
            }
        }
    }
}
