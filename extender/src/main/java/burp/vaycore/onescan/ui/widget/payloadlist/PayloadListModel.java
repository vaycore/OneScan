package burp.vaycore.onescan.ui.widget.payloadlist;

import burp.vaycore.onescan.common.L;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * 列表适配器
 * <p>
 * Created by vaycore on 2022-09-04.
 */
public class PayloadListModel extends AbstractTableModel {

    private final String[] COLUMN_NAMES = new String[]{
            L.get("payload_table_columns.rule"),
    };
    private final Vector<PayloadItem> mData;

    public PayloadListModel() {
        this(null);
    }

    public PayloadListModel(List<PayloadItem> data) {
        if (data == null) {
            data = new ArrayList<>();
        }
        mData = new Vector<>(data);
    }

    public void add(PayloadItem item) {
        if (item == null || item.getRule() == null) {
            return;
        }
        int id = size();
        this.mData.add(item);
        fireTableRowsInserted(id, id);
    }

    public void clearAll() {
        mData.clear();
        fireTableDataChanged();
    }

    public int size() {
        return mData.size();
    }

    public PayloadItem get(int index) {
        return mData.get(index);
    }

    public void set(int index, PayloadItem item) {
        if (item == null || item.getRule() == null) {
            return;
        }
        mData.set(index, item);
        fireTableRowsUpdated(index, index);
    }

    public void remove(int index) {
        mData.remove(index);
        fireTableRowsDeleted(index, index);
    }

    public ArrayList<PayloadItem> getDataList() {
        return new ArrayList<>(mData);
    }

    @Override
    public int getRowCount() {
        return mData.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        PayloadItem data = mData.get(rowIndex);
        if (columnIndex == 0) {
            return data.getRule().toDescribe();
        }
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex != 0) {
            return;
        }
        PayloadItem item = get(rowIndex);
        set(rowIndex, item);
    }
}