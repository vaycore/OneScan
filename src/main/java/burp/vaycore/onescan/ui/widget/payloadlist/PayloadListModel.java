package burp.vaycore.onescan.ui.widget.payloadlist;

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

    private final String[] COLUMN_NAMES = new String[]{"", "Rule"};
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
        item.setId(id);
        this.mData.add(item);
        fireTableRowsInserted(id, id);
    }

    public void clearAll() {
        int size = size();
        mData.clear();
        fireTableRowsDeleted(0, size - 1);
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

    public synchronized ArrayList<PayloadItem> getDataList(boolean onlyEnabled) {
        ArrayList<PayloadItem> result = new ArrayList<>();
        mData.stream()
                .filter(payloadItem -> !onlyEnabled || payloadItem.isEnabled())
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
        PayloadItem data = mData.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return data.isEnabled();
            case 1:
                return data.getRule().toDescribe();
        }
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Boolean.class;
            case 1:
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
        return columnIndex == 0;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex != 0) {
            return;
        }
        PayloadItem item = get(rowIndex);
        item.setEnabled((Boolean) aValue);
        set(rowIndex, item);
    }
}