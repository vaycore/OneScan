package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.CollectData;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.CollectFilter;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

/**
 * 用于展示收集数据的 Table 组件
 * <p>
 * Created by vaycore on 2023-12-23.
 */
public class CollectTable<T> extends JTable implements ActionListener {

    private final CollectTableModel<T> mTableModel;
    private final TableRowSorter<CollectTableModel<T>> mTableRowSorter;

    public CollectTable(CollectTableModel<T> tableModel) {
        if (tableModel == null) {
            throw new IllegalArgumentException("tableModel is null.");
        }
        mTableModel = tableModel;
        setModel(mTableModel);
        setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        mTableRowSorter = new TableRowSorter<>(mTableModel);
        setRowSorter(mTableRowSorter);
        // 不可拖动表头
        getTableHeader().setReorderingAllowed(false);
        // 设置列宽参数
        initColumnWidth();
        // 初始化监听器
        initEvent();
    }

    private void initColumnWidth() {
        setColumnWidth(0, 70);
        setColumnWidth(1, 150);
        setColumnWidth(2, 200);
    }

    private void setColumnWidth(int columnIndex, int width) {
        getColumnModel().getColumn(columnIndex).setPreferredWidth(width);
    }

    private void initEvent() {
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                // 鼠标右键事件
                if (e.getButton() == MouseEvent.BUTTON3) {
                    showPopupMenu(e.getX(), e.getY());
                }
            }
        });
    }

    private void showPopupMenu(int x, int y) {
        JPopupMenu menu = new JPopupMenu();
        // 根据列名，动态构建复制选中项的菜单
        for (int i = 1; i < mTableModel.getColumnCount(); i++) {
            String columnName = mTableModel.getColumnName(i);
            addPopupMenuItem(menu, "复制选中的" + columnName, "copy-column-" + i);
        }
        menu.setLightWeightPopupEnabled(true);
        // 显示菜单
        menu.show(this, x, y);
    }

    private void addPopupMenuItem(JPopupMenu menu, String name, String actionCommand) {
        JMenuItem item = new JMenuItem(name);
        item.setActionCommand(actionCommand);
        item.addActionListener(this);
        menu.add(item);
    }

    /**
     * 设置过滤器
     */
    public void setRowFilter(CollectFilter<T> filter) {
        mTableRowSorter.setRowFilter(filter);
    }

    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        try {
            JComponent component = (JComponent) super.prepareRenderer(renderer, row, column);
            if (component instanceof JLabel) {
                ((JLabel) component).setHorizontalAlignment(JLabel.LEFT);
            }
            return component;
        } catch (Exception e) {
            return super.prepareRenderer(renderer, row, column);
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        if (!action.startsWith("copy-column-")) {
            return;
        }
        String columnIndexStr = action.replace("copy-column-", "");
        int columnIndex = StringUtils.parseInt(columnIndexStr);
        int[] selectedRows = getSelectedRows();
        Set<String> result = new LinkedHashSet<>(selectedRows.length);
        for (int rowIndex : selectedRows) {
            int index = convertRowIndexToModel(rowIndex);
            String value = String.valueOf(mTableModel.getValueAt(index, columnIndex));
            if (StringUtils.isEmpty(value)) {
                continue;
            }
            result.add(value);
        }
        // 如果有数据，复制
        if (result.size() > 0) {
            String value = StringUtils.join(result, "\n");
            Utils.setSysClipboardText(value);
        }
    }

    /**
     * 数据收集表 TableModel 类
     *
     * @param <T> 数据实体类
     */
    public static abstract class CollectTableModel<T> extends AbstractTableModel {

        private final Vector<String> mColumnNames = new Vector<>();
        private final ArrayList<CollectData<T>> mData;

        public CollectTableModel() {
            mData = new ArrayList<>();
            initColumnNames();
        }

        private void initColumnNames() {
            mColumnNames.add("#");
            mColumnNames.add("Domain");
            String[] columnNames = buildColumnNames();
            if (columnNames == null || columnNames.length <= 0) {
                return;
            }
            mColumnNames.addAll(Arrays.asList(columnNames));
        }

        /**
         * 构建数据的列名
         */
        protected abstract String[] buildColumnNames();

        public void add(CollectData<T> data) {
            if (data == null) {
                return;
            }
            synchronized (this.mData) {
                int index = mData.size();
                data.setId(index);
                this.mData.add(data);
                fireTableRowsInserted(index, index);
            }
        }

        /**
         * 设置列表的数据
         *
         * @param list 列表实例
         */
        public void setList(ArrayList<CollectData<T>> list) {
            if (list == null) {
                return;
            }
            this.mData.clear();
            this.mData.addAll(list);
            fireTableDataChanged();
        }

        /**
         * 清空所有数据
         */
        public synchronized void clearAll() {
            this.mData.clear();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return mData.size();
        }

        @Override
        public final int getColumnCount() {
            return mColumnNames.size();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            CollectData<T> data = mData.get(rowIndex);
            if (columnIndex < 2) {
                switch (columnIndex) {
                    case 0:
                        return data.getId();
                    case 1:
                        return data.getDomain();
                }
                return "";
            }
            return buildItemValue(data.getData(), columnIndex - 2);
        }

        protected abstract Object buildItemValue(T data, int columnIndex);

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return ClassUtils.getTypeByFieldId(TaskData.class, columnIndex);
        }

        @Override
        public final String getColumnName(int column) {
            return mColumnNames.get(column);
        }
    }
}
