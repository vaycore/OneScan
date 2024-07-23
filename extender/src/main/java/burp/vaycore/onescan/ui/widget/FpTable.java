package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 指纹列表
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpTable extends JTable {

    private final FpTable.FpTableModel mTableModel = new FpTable.FpTableModel();
    private final TableRowSorter<FpTable.FpTableModel> mTableRowSorter;

    public FpTable() {
        this.setModel(this.mTableModel);
        this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        this.mTableRowSorter = new TableRowSorter<>(this.mTableModel);
        this.setRowSorter(this.mTableRowSorter);
        this.getTableHeader().setReorderingAllowed(false);
        this.initColumnWidth();
        this.loadData();
    }

    public void loadData() {
        ArrayList<FpData> list = FpManager.getList();
        this.mTableModel.setData(list);
    }

    public void reloadData() {
        String path = FpManager.getPath();
        FpManager.init(path);
        ArrayList<FpData> list = FpManager.getList();
        this.mTableModel.setData(list);
    }

    private void initColumnWidth() {
        this.setColumnWidth(0, 125);
        this.setColumnWidth(1, 150);
        this.setColumnWidth(2, 70);
        this.setColumnWidth(3, 70);
        this.setColumnWidth(4, 150);
        this.setColumnWidth(5, 150);
        this.setColumnWidth(6, 150);
    }

    private void setColumnWidth(int columnIndex, int width) {
        this.getColumnModel().getColumn(columnIndex).setPreferredWidth(width);
    }

    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        JComponent component = (JComponent) super.prepareRenderer(renderer, row, column);
        if (component instanceof JLabel) {
            ((JLabel) component).setHorizontalAlignment(JLabel.LEFT);
        }

        return component;
    }

    public void setRowFilter(RowFilter<FpTable.FpTableModel, Integer> filter) {
        this.mTableRowSorter.setRowFilter(filter);
    }

    public void addFpData(FpData data) {
        this.mTableModel.add(data);
        FpManager.addItem(data);
    }

    public void removeFpData(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < this.mTableModel.getRowCount()) {
            int index = this.convertRowIndexToModel(rowIndex);
            this.mTableModel.remove(index);
            FpManager.removeItem(index);
        }
    }

    public void setFpData(int rowIndex, FpData data) {
        if (rowIndex >= 0 && rowIndex < this.mTableModel.getRowCount()) {
            int index = this.convertRowIndexToModel(rowIndex);
            this.mTableModel.set(index, data);
            FpManager.setItem(index, data);
        }
    }

    public FpData getFpData(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < this.mTableModel.getRowCount()) {
            int index = this.convertRowIndexToModel(rowIndex);
            return this.mTableModel.mData.get(index);
        } else {
            return null;
        }
    }

    public static class FpTableModel extends AbstractTableModel {

        public static final String[] COLUMN_NAMES = new String[]{
                "Name", "Company", "Lang", "SoftHard", "Frame", "ParentCategory", "Category"};
        private final ArrayList<FpData> mData = new ArrayList<>();

        public void add(FpData data) {
            if (data != null) {
                synchronized (this.mData) {
                    int id = this.mData.size();
                    this.mData.add(data);
                    this.fireTableRowsInserted(id, id);
                }
            }
        }

        public void remove(int index) {
            synchronized (this.mData) {
                this.mData.remove(index);
                this.fireTableRowsDeleted(index, index);
            }
        }

        public void set(int index, FpData data) {
            if (data != null) {
                synchronized (this.mData) {
                    this.mData.set(index, data);
                    this.fireTableRowsUpdated(index, index);
                }
            }
        }

        public void setData(List<FpData> data) {
            if (data != null) {
                synchronized (this.mData) {
                    this.mData.clear();
                    if (!data.isEmpty()) {
                        this.mData.addAll(data);
                    }

                    this.fireTableDataChanged();
                }
            }
        }

        public int getRowCount() {
            return this.mData.size();
        }

        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        public Object getValueAt(int rowIndex, int columnIndex) {
            FpData data = this.mData.get(rowIndex);
            return ClassUtils.getValueByFieldId(data, columnIndex);
        }

        public Class<?> getColumnClass(int columnIndex) {
            return ClassUtils.getTypeByFieldId(TaskData.class, columnIndex);
        }

        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }
    }
}
