package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.TaskData;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;

/**
 * 任务列表
 * <p>
 * Created by vaycore on 2022-08-10.
 */
public class TaskTable extends JTable {

    private final TaskTableModel mTaskTableModel;
    private final Color mItemBgColor;
    private final Color mItemSelectColor;
    private final Color mItemBgColor2;
    private OnTaskTableEventListener mOnTaskTableEventListener;
    private int mLastSelectedRow;

    private final MouseListener mMenuItemClick = new MouseAdapter() {
        @Override
        public void mousePressed(MouseEvent e) {
            super.mousePressed(e);
            JMenuItem item = (JMenuItem) e.getComponent();
            String action = item.getActionCommand();
            int[] selectedRows = getSelectedRows();
            switch (action) {
                case "clean-all":
                    mTaskTableModel.clearAll();
                    if (mOnTaskTableEventListener != null) {
                        mOnTaskTableEventListener.onChangeSelection(null);
                    }
                    mLastSelectedRow = -1;
                    break;
                case "send-to-repeater":
                    ArrayList<TaskData> newData = new ArrayList<>(selectedRows.length);
                    for (int index : selectedRows) {
                        int realIndex = convertRowIndexToModel(index);
                        TaskData data = mTaskTableModel.mData.get(realIndex);
                        newData.add(data);
                    }
                    if (mOnTaskTableEventListener != null) {
                        mOnTaskTableEventListener.onSendToRepeater(newData);
                    }
                    break;
            }
        }
    };

    @Override
    public TableCellRenderer getCellRenderer(int row, int column) {
        TableCellRenderer renderer = super.getCellRenderer(row, column);
        return new TableCellRenderer() {

            private Color defaultItemColor(int index, boolean isSelected) {
                Color result = mItemBgColor;
                if (index % 2 == 0) {
                    result = mItemBgColor2;
                }
                if (isSelected) {
                    result = mItemSelectColor;
                }
                return result;
            }

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int rowIndex, int columnIndex) {
                Component c = renderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, rowIndex, columnIndex);
                int index = convertRowIndexToModel(rowIndex);
                TaskData data = mTaskTableModel.mData.get(index);
                String highlight = data.getHighlight();
                Color bgColor;
                // 检测是否需要显示高亮颜色
                if (StringUtils.isEmpty(highlight)) {
                    bgColor = defaultItemColor(rowIndex, isSelected);
                    c.setBackground(bgColor);
                    return c;
                }
                // 处理高亮颜色
                bgColor = findColorByName(highlight);
                if (bgColor == null) {
                    bgColor = defaultItemColor(rowIndex, isSelected);
                    c.setBackground(bgColor);
                    return c;
                }
                // 高亮颜色选中处理
                if (isSelected) {
                    bgColor = darkerColor(bgColor);
                }
                c.setBackground(bgColor);
                return c;
            }
        };
    }

    public TaskTable() {
        mTaskTableModel = new TaskTableModel();
        mLastSelectedRow = -1;
        setModel(mTaskTableModel);
        setAutoCreateRowSorter(true);
        setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        setRowSorter(new TableRowSorter<>(getModel()));
        // 不可拖动表头
        getTableHeader().setReorderingAllowed(false);
        // 设置列宽参数
        initColumnWidth();
        // 初始化监听器
        initEvent();
        // 保存原表格的几种颜色
        mItemBgColor = getTableBgColor(false);
        mItemBgColor2 = UIManager.getColor("Table.alternateRowColor");
        mItemSelectColor = getTableBgColor(true);
    }

    private Color getTableBgColor(boolean isSelected) {
        TableCellRenderer renderer = getDefaultRenderer(String.class);
        return renderer.getTableCellRendererComponent(this, "",
                isSelected, false, 0, 0).getBackground();
    }

    private void initEvent() {
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                // 鼠标右键事件
                if (e.getButton() == 3) {
                    showPopupMenu(e.getX(), e.getY());
                }
            }
        });
    }

    private void initColumnWidth() {
        setColumnWidth(0, 70);
        setColumnWidth(1, 70);
        setColumnWidth(2, 200);
        setColumnWidth(3, 350);
        setColumnWidth(4, 200);
        setColumnWidth(5, 125);
        setColumnWidth(6, 50);
        setColumnWidth(7, 100);
        setColumnWidth(8, 200);
    }

    private void setColumnWidth(int columnIndex, int width) {
        getColumnModel().getColumn(columnIndex).setPreferredWidth(width);
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
        // 当其它行被选中时，调用监听器
        if (mLastSelectedRow != rowIndex && mOnTaskTableEventListener != null) {
            mLastSelectedRow = rowIndex;
            TaskData data = getTaskData(rowIndex);
            mOnTaskTableEventListener.onChangeSelection(data);
        }
    }

    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        JComponent component = (JComponent) super.prepareRenderer(renderer, row, column);
        if (component instanceof JLabel) {
            ((JLabel) component).setHorizontalAlignment(JLabel.LEFT);
        }
        return component;
    }

    private void showPopupMenu(int x, int y) {
        JPopupMenu menu = new JPopupMenu();
        // 清空所有记录
        JMenuItem clearAll = new JMenuItem("清空所有记录");
        clearAll.setActionCommand("clean-all");
        clearAll.addMouseListener(mMenuItemClick);
        menu.add(clearAll);

        // 发送到 Repeater
        JMenuItem sendToRepeater = new JMenuItem("发送选中项到Repeater");
        sendToRepeater.setActionCommand("send-to-repeater");
        sendToRepeater.addMouseListener(mMenuItemClick);
        menu.add(sendToRepeater);
        menu.setLightWeightPopupEnabled(true);

        // 显示菜单
        menu.show(this, x, y);
    }

    private Color findColorByName(String colorName) {
        switch (colorName) {
            case "red":
                return Color.decode("#FF555D");
            case "orange":
                return Color.decode("#FFC54D");
            case "yellow":
                return Color.decode("#FFFF3A");
            case "green":
                return Color.decode("#00FF45");
            case "cyan":
                return Color.decode("#00FFFF");
            case "blue":
                return Color.decode("#6464FF");
            case "pink":
                return Color.decode("#FFC5C7");
            case "magenta":
                return Color.decode("#FF55FF");
            case "gray":
                return Color.decode("#B4B4B4");
            default:
                break;
        }
        return null;
    }

    private Color darkerColor(Color color) {
        return new Color(Math.max((int) (color.getRed() * 0.85D), 0),
                Math.max((int) (color.getGreen() * 0.85D), 0),
                Math.max((int) (color.getBlue() * 0.85D), 0),
                color.getAlpha());
    }

    /**
     * 设置监听器
     *
     * @param l 监听器实现类
     */
    public void setOnTaskTableEventListener(OnTaskTableEventListener l) {
        this.mOnTaskTableEventListener = l;
    }

    /**
     * 添加展示的任务数据
     *
     * @param data 数据
     */
    public void addTaskData(TaskData data) {
        mTaskTableModel.add(data);
    }

    /**
     * 获取任务数据
     *
     * @param rowIndex 数据所在下标
     * @return 任务数据
     */
    private TaskData getTaskData(int rowIndex) {
        return mTaskTableModel.mData.get(convertRowIndexToModel(rowIndex));
    }

    /**
     * 监听器
     */
    public interface OnTaskTableEventListener {
        /**
         * 切换选中行监听
         *
         * @param data 数据对象。为null表示列表已清空
         */
        void onChangeSelection(TaskData data);

        /**
         * 发送到 BurpSuite 的 Repeater 模块
         *
         * @param list 数据列表
         */
        void onSendToRepeater(ArrayList<TaskData> list);
    }

    /**
     * 列表适配器
     */
    private static class TaskTableModel extends AbstractTableModel {

        private final String[] COLUMN_NAMES = new String[]{
                "#", "Method", "Host", "Url", "Title", "IP", "Status", "Length", "Comment"};
        private final ArrayList<TaskData> mData;

        public TaskTableModel() {
            mData = new ArrayList<>();
        }

        public void add(TaskData data) {
            if (data == null || data.getReqResp() == null) {
                return;
            }
            synchronized (this.mData) {
                int id = this.mData.size();
                data.setId(id);
                this.mData.add(data);
                fireTableRowsInserted(id, id);
            }
        }

        public void clearAll() {
            synchronized (this.mData) {
                int size = this.mData.size();
                mData.clear();
                fireTableRowsDeleted(0, size - 1);
            }
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
            TaskData data = mData.get(rowIndex);
            return ClassUtils.getValueByFieldId(data, columnIndex);
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return ClassUtils.getTypeByFieldId(TaskData.class, columnIndex);
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }
    }
}
