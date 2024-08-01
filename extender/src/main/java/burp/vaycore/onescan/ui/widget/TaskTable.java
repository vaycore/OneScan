package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.filter.FilterRule;
import burp.vaycore.common.filter.TableFilter;
import burp.vaycore.common.helper.IconHash;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.TaskData;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 任务列表
 * <p>
 * Created by vaycore on 2022-08-10.
 */
public class TaskTable extends JTable implements ActionListener {

    private final TaskTableModel mTaskTableModel;
    private final TableRowSorter<TaskTableModel> mTableRowSorter;
    private ArrayList<TableFilter<AbstractTableModel>> mLastFilters;
    private final ArrayList<TableFilter<AbstractTableModel>> mTempFilters;
    private OnTaskTableEventListener mOnTaskTableEventListener;
    private int mLastSelectedRow;

    @Override
    public TableCellRenderer getCellRenderer(int row, int column) {
        TableCellRenderer renderer = super.getCellRenderer(row, column);
        return new TableCellRenderer() {

            private Color defaultItemColor(int index, boolean isSelected) {
                Color result = UIManager.getColor("Table.background");
                if (index % 2 == 0) {
                    result = UIManager.getColor("Table.alternateRowColor");
                }
                if (isSelected) {
                    result = UIManager.getColor("Table.selectionBackground");
                    if (result == null) {
                        result = darkerColor(UIManager.getColor("Table.background"));
                    }
                }
                return result;
            }

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int rowIndex, int columnIndex) {
                Component c = renderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, rowIndex, columnIndex);
                TaskData data = getTaskData(rowIndex);
                String highlight = data.getHighlight();
                Color bgColor = findColorByName(highlight);
                Color fontColor = UIManager.getColor("Table.foreground");
                // 检测是否需要显示高亮颜色
                if (bgColor == null) {
                    bgColor = defaultItemColor(rowIndex, isSelected);
                    c.setBackground(bgColor);
                    c.setForeground(fontColor);
                    return c;
                } else {
                    fontColor = Color.BLACK;
                }
                // 高亮颜色选中处理
                if (isSelected) {
                    bgColor = darkerColor(bgColor);
                }
                c.setBackground(bgColor);
                c.setForeground(fontColor);
                return c;
            }
        };
    }

    public TaskTable() {
        mTaskTableModel = new TaskTableModel();
        mLastSelectedRow = -1;
        setModel(mTaskTableModel);
        setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        mTempFilters = new ArrayList<>();
        mTableRowSorter = new TableRowSorter<>(mTaskTableModel);
        // 颜色字段等级排序
        mTableRowSorter.setComparator(11, (Comparator<String>) (left, right) -> {
            int leftLevel = findColorLevelByName(left);
            int rightLevel = findColorLevelByName(right);
            return Integer.compare(leftLevel, rightLevel);
        });
        setRowSorter(mTableRowSorter);
        // 不可拖动表头
        getTableHeader().setReorderingAllowed(false);
        // 设置列宽参数
        initColumnWidth();
        // 初始化监听器
        initEvent();
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

    private void initColumnWidth() {
        setColumnWidth(0, 70);
        setColumnWidth(1, 50);
        setColumnWidth(2, 70);
        setColumnWidth(3, 200);
        setColumnWidth(4, 200);
        setColumnWidth(5, 200);
        setColumnWidth(6, 125);
        setColumnWidth(7, 50);
        setColumnWidth(8, 100);
        setColumnWidth(9, 200);
        setColumnWidth(10, 200);
        setColumnWidth(11, 85);
    }

    private void setColumnWidth(int columnIndex, int width) {
        getColumnModel().getColumn(columnIndex).setPreferredWidth(width);
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
        int index = convertRowIndexToModel(rowIndex);
        // 当其它行被选中时，调用监听器
        if (mLastSelectedRow != index && mOnTaskTableEventListener != null) {
            mLastSelectedRow = index;
            TaskData data = getTaskData(rowIndex);
            mOnTaskTableEventListener.onChangeSelection(data);
        }
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
            return new JLabel();
        }
    }

    private void showPopupMenu(int x, int y) {
        JPopupMenu menu = new JPopupMenu();
        addPopupMenuItem(menu, "获取bodyMd5值", "fetch-body-md5");
        addPopupMenuItem(menu, "获取bodyHash值", "fetch-body-hash");
        addPopupMenuItem(menu, "发送选中项到Repeater", "send-to-repeater");
        addPopupMenuItem(menu, "添加Host到黑名单", "add-to-black-host");
        addPopupMenuItem(menu, "删除选中项", "remove-items");
        addPopupMenuItem(menu, "清空所有记录", "clean-all");
        addTempFilterMenuItem(menu);
        addPopupMenuItem(menu, "清空临时过滤规则", "clean-temp-filter");
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

    private void addTempFilterMenuItem(JPopupMenu menu) {
        JMenu root = new JMenu("临时过滤选中数据");
        int selectedColumn = getSelectedColumn();
        // 处理未选中的情况
        if (selectedColumn < 0) {
            selectedColumn = 0;
        }
        // 选中的列置顶
        String topName = TaskTableModel.COLUMN_NAMES[selectedColumn];
        JMenuItem topItem = new JMenuItem(topName);
        topItem.setActionCommand("temp-filter-item-" + topName);
        topItem.addActionListener(this);
        root.add(topItem);
        // 添加其它的列
        for (int i = 0; i < TaskTableModel.COLUMN_NAMES.length; i++) {
            if (i == selectedColumn) {
                continue;
            }
            String itemName = TaskTableModel.COLUMN_NAMES[i];
            JMenuItem menuItem = new JMenuItem(itemName);
            menuItem.setActionCommand("temp-filter-item-" + itemName);
            menuItem.addActionListener(this);
            root.add(menuItem);
        }
        menu.add(root);
    }

    private Color findColorByName(String colorName) {
        if (StringUtils.isEmpty(colorName)) {
            return null;
        }
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

    private static int findColorLevelByName(String colorName) {
        if (StringUtils.isEmpty(colorName)) {
            return 0;
        }
        switch (colorName) {
            case "red":
                return 9;
            case "orange":
                return 8;
            case "yellow":
                return 7;
            case "green":
                return 6;
            case "cyan":
                return 5;
            case "blue":
                return 4;
            case "pink":
                return 3;
            case "magenta":
                return 2;
            case "gray":
                return 1;
            default:
                return 0;
        }
    }

    private Color darkerColor(Color color) {
        return new Color(Math.max((int) (color.getRed() * 0.85D), 0),
                Math.max((int) (color.getGreen() * 0.85D), 0),
                Math.max((int) (color.getBlue() * 0.85D), 0),
                color.getAlpha());
    }

    /**
     * 设置过滤器
     */
    public void setRowFilter(ArrayList<TableFilter<AbstractTableModel>> filters) {
        if (filters == null) {
            filters = new ArrayList<>();
        }
        mLastFilters = filters;
        ArrayList<TableFilter<AbstractTableModel>> localFilter = new ArrayList<>(filters);
        if (mTempFilters != null && !mTempFilters.isEmpty()) {
            localFilter.addAll(mTempFilters);
        }
        mTableRowSorter.setRowFilter(RowFilter.andFilter(localFilter));
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
        int index = convertRowIndexToModel(rowIndex);
        return mTaskTableModel.mData.get(index);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        JMenuItem item = (JMenuItem) e.getSource();
        String action = item.getActionCommand();
        int[] selectedRows = getSelectedRows();
        switch (action) {
            case "fetch-body-md5":
            case "fetch-body-hash":
                if (mOnTaskTableEventListener == null) {
                    break;
                }
                String result = fetchDataByAction(action, selectedRows);
                showTextAreaDialog(item.getText(), result);
                break;
            case "send-to-repeater":
                ArrayList<TaskData> newData = new ArrayList<>(selectedRows.length);
                for (int index : selectedRows) {
                    TaskData data = getTaskData(index);
                    newData.add(data);
                }
                if (mOnTaskTableEventListener != null) {
                    mOnTaskTableEventListener.onSendToRepeater(newData);
                }
                break;
            case "add-to-black-host":
                if (mOnTaskTableEventListener == null) {
                    break;
                }
                ArrayList<String> hosts = getSelectedHosts(selectedRows);
                mOnTaskTableEventListener.addToBlackHost(hosts);
                break;
            case "remove-items":
                ArrayList<TaskData> removeList = new ArrayList<>();
                for (int index : selectedRows) {
                    TaskData data = getTaskData(index);
                    removeList.add(data);
                }
                mTaskTableModel.removeItems(removeList);
                break;
            case "clean-all":
                clearAll();
                break;
            case "clean-temp-filter":
                clearTempFilter();
                break;
            default:
                // 处理临时过滤事件
                onTempFilterEvent(action, selectedRows);
                break;
        }
    }

    /**
     * 根据 action 获取数据
     *
     * @param action       action
     * @param selectedRows 选中行
     * @return 失败返回空字符串
     */
    private String fetchDataByAction(String action, int[] selectedRows) {
        StringBuilder result = new StringBuilder();
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            byte[] bodyBytes = mOnTaskTableEventListener.getBodyByTaskData(data);
            String value;
            switch (action) {
                case "fetch-body-md5":
                    value = Utils.md5(bodyBytes);
                    break;
                case "fetch-body-hash":
                default:
                    value = IconHash.hash(bodyBytes);
                    break;
            }
            if (!StringUtils.isEmpty(result)) {
                result.append("\n\n");
            }
            result.append(String.format("#%d：\n%s", data.getId(), value));
        }
        return result.toString();
    }

    /**
     * 获取当前选中的 Host 数据列表
     *
     * @param selectedRows 选择的行下标
     * @return Host 列表
     */
    private ArrayList<String> getSelectedHosts(int[] selectedRows) {
        ArrayList<String> hosts = new ArrayList<>();
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            try {
                String host = new URL(data.getHost()).getHost();
                if (!hosts.contains(host)) {
                    hosts.add(host);
                }
            } catch (MalformedURLException ex) {
                Logger.error(ex.getMessage());
            }
        }
        return hosts;
    }

    /**
     * 处理临时过滤事件
     *
     * @param action       对应 action 值
     * @param selectedRows 选中项
     */
    private void onTempFilterEvent(String action, int[] selectedRows) {
        if (action == null || !action.startsWith("temp-filter-item-")) {
            return;
        }
        String columnName = action.replace("temp-filter-item-", "");
        int columnIndex = findColumnIndexByName(columnName);
        if (columnIndex < 0) {
            return;
        }
        FilterRule rule = getTempFilterRuleByColumn(columnIndex);
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            Object objValue = ClassUtils.getValueByFieldId(data, columnIndex);
            String value = "";
            if (objValue != null) {
                value = String.valueOf(objValue);
            }
            if (checkTempFilterRuleRepeat(rule, value)) {
                continue;
            }
            int logic = 0;
            if (!rule.getItems().isEmpty()) {
                logic = FilterRule.LOGIC_AND;
            }
            rule.addRule(logic, FilterRule.OPERATE_NOT_EQUAL, value);
        }
        // 检测规则表是否为空
        if (!rule.getItems().isEmpty()) {
            mTempFilters.add(new TableFilter<>(rule));
        }
        // 更新过滤规则
        setRowFilter(mLastFilters);
    }

    /**
     * 根据列名获取列下标
     *
     * @param columnName 列名
     * @return 失败返回-1
     */
    private int findColumnIndexByName(String columnName) {
        for (int i = 0; i < TaskTableModel.COLUMN_NAMES.length; i++) {
            String name = TaskTableModel.COLUMN_NAMES[i];
            if (name.equals(columnName)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 根据列下标，获取临时过滤的 FilterRule 实例
     *
     * @param columnIndex 对应的列下标
     * @return 未找到返回一个新创建的 FilterRule 实例
     */
    private FilterRule getTempFilterRuleByColumn(int columnIndex) {
        FilterRule result = new FilterRule(columnIndex);
        if (mTempFilters == null || mLastFilters.isEmpty()) {
            return result;
        }
        for (TableFilter<AbstractTableModel> item : mTempFilters) {
            FilterRule rule = item.getRule();
            if (rule.getColumnIndex() == columnIndex) {
                return rule;
            }
        }
        return result;
    }

    /**
     * 检查临时过滤规则实例，是否存在重复规则
     *
     * @param rule  规则实例
     * @param value 规则值
     * @return true=重复；false=不重复
     */
    private boolean checkTempFilterRuleRepeat(FilterRule rule, String value) {
        ArrayList<FilterRule.Item> items = rule.getItems();
        if (items.isEmpty()) {
            return false;
        }
        for (FilterRule.Item item : items) {
            if (value.equals(item.getValue())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 清空所有记录
     */
    public void clearAll() {
        mTaskTableModel.clearAll();
        if (mOnTaskTableEventListener != null) {
            mOnTaskTableEventListener.onChangeSelection(null);
        }
        mLastSelectedRow = -1;
        // 同时清除临时过滤规则
        clearTempFilter();
    }

    /**
     * 清除临时过滤规则
     */
    private void clearTempFilter() {
        mTempFilters.clear();
        setRowFilter(mLastFilters);
    }

    private static void showTextAreaDialog(String title, String text) {
        JPanel panel = new JPanel();
        panel.setPreferredSize(new Dimension(400, 150));
        panel.setLayout(new VLayout());
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        JScrollPane pane = new JScrollPane(area);
        panel.add(pane, "1w");
        UIHelper.showCustomDialog(title, new String[]{"Close"}, panel);
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

        /**
         * 获取 TaskData 中包含的响应 Body 字节数据
         *
         * @param data TaskData 实例
         * @return 响应 Body 字节数据
         */
        byte[] getBodyByTaskData(TaskData data);

        /**
         * 添加 Host 列表到黑名单
         *
         * @param hosts 黑名单列表
         */
        void addToBlackHost(ArrayList<String> hosts);
    }

    /**
     * 列表适配器
     */
    public static class TaskTableModel extends AbstractTableModel {

        public static final String[] COLUMN_NAMES = new String[]{
                "#", "From", "Method", "Host", "Url", "Title", "IP", "Status", "Length", "Fingerprint", "Comment", "Color"};
        private final ArrayList<TaskData> mData;
        private final AtomicInteger mCounter;

        public TaskTableModel() {
            mData = new ArrayList<>();
            mCounter = new AtomicInteger();
        }

        public void add(TaskData data) {
            if (data == null || data.getReqResp() == null) {
                return;
            }
            synchronized (this.mData) {
                int index = mData.size();
                int id = mCounter.getAndIncrement();
                data.setId(id);
                this.mData.add(data);
                fireTableRowsInserted(index, index);
            }
        }

        public void removeItems(List<TaskData> list) {
            if (list == null || list.isEmpty()) {
                return;
            }
            synchronized (this.mData) {
                this.mData.removeAll(list);
                fireTableDataChanged();
            }
        }

        public void clearAll() {
            synchronized (this.mData) {
                mData.clear();
                mCounter.set(0);
                fireTableDataChanged();
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
