package burp.vaycore.onescan.ui.widget.payloadlist;

import burp.vaycore.onescan.common.L;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * <p>
 * Created by vaycore on 2023-11-07.
 */
public class ProcessingListModel extends AbstractTableModel {

    private final String[] COLUMN_NAMES = new String[]{
            L.get("processing_table_columns.enabled"),
            L.get("processing_table_columns.merge"),
            L.get("processing_table_columns.rule_name"),
            L.get("processing_table_columns.rule_count"),
    };
    private final Vector<ProcessingItem> mData;

    public ProcessingListModel() {
        this(null);
    }

    public ProcessingListModel(List<ProcessingItem> data) {
        if (data == null) {
            mData = new Vector<>();
        } else {
            mData = new Vector<>(data);
        }
    }

    public void add(ProcessingItem item) {
        if (item == null || item.getItems() == null) {
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

    public ProcessingItem get(int index) {
        return mData.get(index);
    }

    public void set(int index, ProcessingItem item) {
        if (item == null || item.getItems() == null) {
            return;
        }
        mData.set(index, item);
        fireTableRowsUpdated(index, index);
    }

    public void remove(int index) {
        mData.remove(index);
        fireTableRowsDeleted(index, index);
    }

    public synchronized ArrayList<ProcessingItem> getDataList(boolean onlyEnabled) {
        ArrayList<ProcessingItem> result = new ArrayList<>();
        mData.stream()
                .filter(ProcessingItem -> !onlyEnabled || ProcessingItem.isEnabled())
                .forEach(result::add);
        return result;
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
        ProcessingItem data = mData.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return data.isEnabled();
            case 1:
                return data.isMerge();
            case 2:
                return data.getName();
            case 3:
                ArrayList<PayloadItem> items = data.getItems();
                int count = items == null ? 0 : items.size();
                return String.valueOf(count);
        }
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
            case 1:
                return Boolean.class;
            case 2:
            case 3:
                return String.class;
        }
        return String.class;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0 || columnIndex == 1;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        ProcessingItem item = get(rowIndex);
        if (columnIndex == 0) {
            item.setEnabled((Boolean) aValue);
        } else if (columnIndex == 1) {
            item.setMerge((Boolean) aValue);
        }
        set(rowIndex, item);
    }
}
