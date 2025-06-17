package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.filter.FilterRule;
import burp.vaycore.common.filter.TableFilter;
import burp.vaycore.common.helper.DataTableItemLoader;
import burp.vaycore.common.helper.IconHash;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;

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
import java.util.List;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * 任务列表
 * <p>
 * Created by vaycore on 2022-08-10.
 */
public class TaskTable extends JTable implements ActionListener {

    /**
     * 预设的列宽
     */
    private static final int[] PRE_COLUMN_WIDTH = {
            70, // #
            65, // From
            70, // Method
            200, // Host
            200, // Url
            200, // Title
            125, // IP
            70, // Status
            100, // Length
            70, // Color
    };

    private static Vector<String> sColumnNames;

    private final TaskTableModel mTaskTableModel;
    private TableRowSorter<TaskTableModel> mTableRowSorter;
    private ArrayList<TableFilter<AbstractTableModel>> mTableFilters = new ArrayList<>();
    private final ArrayList<TableFilter<AbstractTableModel>> mTempFilters = new ArrayList<>();
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
                String highlight = "";
                if (data != null) {
                    highlight = data.getHighlight();
                }
                Color bgColor = FpManager.findColorByName(highlight);
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
        // 不可拖动表头
        getTableHeader().setReorderingAllowed(false);
        mTableRowSorter = new TableRowSorter<>(mTaskTableModel);
        // 初始化颜色等级排序
        initColorLevelSorter();
        // 初始化列宽
        initColumnWidth();
        // 设置排序器
        setRowSorter(mTableRowSorter);
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

    /**
     * 初始化颜色等级排序
     */
    private void initColorLevelSorter() {
        // 颜色字段等级排序（固定最后一列为颜色等级）
        int comparatorColumn = TaskTableModel.PRE_COLUMN_NAMES.length - 1;
        mTableRowSorter.setComparator(comparatorColumn, (Comparator<String>) (left, right) -> {
            int leftLevel = getColorLevel(left);
            int rightLevel = getColorLevel(right);
            return Integer.compare(leftLevel, rightLevel);
        });
    }

    /**
     * 初始化列宽
     */
    private void initColumnWidth() {
        int columnCount = getColumnModel().getColumnCount();
        for (int columnIndex = 0; columnIndex < columnCount; columnIndex++) {
            // 默认宽度
            int columnWidth = 120;
            // 如果在预设宽度范围内
            if (columnIndex < PRE_COLUMN_WIDTH.length) {
                columnWidth = PRE_COLUMN_WIDTH[columnIndex];
            }
            // 设置宽度
            getColumnModel().getColumn(columnIndex).setPreferredWidth(columnWidth);
        }
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
        showPopupMenu(this, x, y);
    }

    public void showPopupMenu(Component invoker, int x, int y) {
        JPopupMenu menu = new JPopupMenu();
        addPopupMenuItem(menu, L.get("task_table_menu.get_body_md5"), "fetch-body-md5");
        addPopupMenuItem(menu, L.get("task_table_menu.get_body_hash"), "fetch-body-hash");
        addPopupMenuItem(menu, L.get("task_table_menu.copy_url"), "copy-url");
        addPopupMenuItem(menu, L.get("task_table_menu.send_to_repeater"), "send-to-repeater");
        addPopupMenuItem(menu, L.get("task_table_menu.add_host_to_blocklist"), "add-host-to-blocklist");
        addPopupMenuItem(menu, L.get("task_table_menu.delete_selected_items"), "remove-items");
        addPopupMenuItem(menu, L.get("task_table_menu.clear_history"), "clean-all");
        addTempFilterMenuItem(menu);
        addPopupMenuItem(menu, L.get("task_table_menu.clear_temp_filter_rules"), "clean-temp-filter");
        menu.setLightWeightPopupEnabled(true);
        // 显示菜单
        menu.show(invoker, x, y);
    }

    private void addPopupMenuItem(JPopupMenu menu, String name, String actionCommand) {
        JMenuItem item = new JMenuItem(name);
        item.setActionCommand(actionCommand);
        item.addActionListener(this);
        menu.add(item);
    }

    private void addTempFilterMenuItem(JPopupMenu menu) {
        JMenu root = new JMenu(L.get("task_table_menu.temp_filter_selected_data"));
        int selectedColumn = getSelectedColumn();
        // 处理未选中的情况
        if (selectedColumn < 0) {
            selectedColumn = 0;
        }
        Vector<String> columnNames = getColumnNames();
        // 选中的列置顶
        String topName = columnNames.get(selectedColumn);
        JMenuItem topItem = new JMenuItem(topName);
        topItem.setActionCommand("temp-filter-item-" + topName);
        topItem.addActionListener(this);
        root.add(topItem);
        // 添加其它的列
        for (int i = 0; i < columnNames.size(); i++) {
            if (i == selectedColumn) {
                continue;
            }
            String itemName = columnNames.get(i);
            JMenuItem menuItem = new JMenuItem(itemName);
            menuItem.setActionCommand("temp-filter-item-" + itemName);
            menuItem.addActionListener(this);
            root.add(menuItem);
        }
        menu.add(root);
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
        mTableFilters = filters;
        updateRowFilter();
    }

    /**
     * 更新过滤器
     */
    public void updateRowFilter() {
        ArrayList<TableFilter<AbstractTableModel>> groupFilter = new ArrayList<>();
        // 过滤规则
        if (mTableFilters != null && !mTableFilters.isEmpty()) {
            groupFilter.addAll(mTableFilters);
        }
        // 临时过滤规则
        if (mTempFilters != null && !mTempFilters.isEmpty()) {
            groupFilter.addAll(mTempFilters);
        }
        // 检测过滤字段是否有效
        ArrayList<TableFilter<AbstractTableModel>> result = new ArrayList<>();
        for (TableFilter<AbstractTableModel> filter : groupFilter) {
            FilterRule rule = filter.getRule();
            // 规则为空检测
            if (rule == null || rule.getItems().isEmpty()) {
                continue;
            }
            int filterColumnIndex = rule.getColumnIndex();
            // 越界检测
            if (filterColumnIndex < 0 || filterColumnIndex >= getColumnCount()) {
                continue;
            }
            // 保留有效的过滤规则
            result.add(filter);
        }
        synchronized (mTaskTableModel) {
            mTableRowSorter.setRowFilter(RowFilter.andFilter(result));
        }
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
        if (rowIndex >= 0 && rowIndex < getRowCount()) {
            int index = convertRowIndexToModel(rowIndex);
            return mTaskTableModel.getItemData(index);
        }
        return null;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        JMenuItem item = (JMenuItem) e.getSource();
        String action = item.getActionCommand();
        int[] selectedRows = getSelectedRows();
        switch (action) {
            case "fetch-body-md5":
            case "fetch-body-hash":
                doFetchBodyAction(action, selectedRows, item);
                break;
            case "copy-url":
                doCopyUrl(selectedRows);
                break;
            case "send-to-repeater":
                doSendToRepeater(selectedRows);
                break;
            case "add-host-to-blocklist":
                doAddHostToBlocklist(selectedRows);
                break;
            case "remove-items":
                doRemoveItems(selectedRows);
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
     * 处理菜单项 fetch-body- 事件
     *
     * @param action       事件名
     * @param selectedRows 选中行
     * @param item         菜单项组件实例（用于获取对话框标题）
     */
    private void doFetchBodyAction(String action, int[] selectedRows, JMenuItem item) {
        if (mOnTaskTableEventListener == null) {
            return;
        }
        String result = fetchBodyDataByAction(action, selectedRows);
        showTextAreaDialog(item.getText(), result);
    }

    /**
     * 根据 action 获取数据
     *
     * @param action       事件名
     * @param selectedRows 选中行
     * @return 失败返回空字符串
     */
    private String fetchBodyDataByAction(String action, int[] selectedRows) {
        StringBuilder result = new StringBuilder();
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            if (data == null) {
                continue;
            }
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
     * 将选中行的 URL，复制到剪切板
     *
     * @param selectedRows 选中行
     */
    private void doCopyUrl(int[] selectedRows) {
        StringBuilder sb = new StringBuilder();
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            if (data == null) {
                return;
            }
            // 以换行区分
            if (StringUtils.isNotEmpty(sb)) {
                sb.append("\n");
            }
            String url = data.getHost() + data.getUrl();
            sb.append(url);
        }
        Utils.setSysClipboardText(sb.toString());
    }

    /**
     * 将选中的数据发送到 BurpSuite 的 Repeater 模块
     *
     * @param selectedRows 选中行
     */
    private void doSendToRepeater(int[] selectedRows) {
        ArrayList<TaskData> newData = new ArrayList<>(selectedRows.length);
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            if (data != null) {
                newData.add(data);
            }
        }
        if (mOnTaskTableEventListener != null) {
            mOnTaskTableEventListener.onSendToRepeater(newData);
        }
    }

    /**
     * 将选中行的 Host 添加到黑名单
     *
     * @param selectedRows 选中行
     */
    private void doAddHostToBlocklist(int[] selectedRows) {
        if (mOnTaskTableEventListener == null) {
            return;
        }
        ArrayList<String> hosts = getSelectedHosts(selectedRows);
        mOnTaskTableEventListener.addHostToBlocklist(hosts);
    }

    /**
     * 从列表中删除选中行的数据
     *
     * @param selectedRows 选中行
     */
    private void doRemoveItems(int[] selectedRows) {
        ArrayList<TaskData> removeList = new ArrayList<>();
        for (int index : selectedRows) {
            TaskData data = getTaskData(index);
            if (data != null) {
                removeList.add(data);
            }
        }
        mTaskTableModel.removeItems(removeList);
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
            if (data == null) {
                continue;
            }
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
            int rowIndex = convertRowIndexToModel(index);
            // 从 TableModel 里拿数据
            Object objValue = mTaskTableModel.getValueAt(rowIndex, columnIndex);
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
            // 如果存在对应列的规则实例，直接设置；如果不存在，添加
            int index = getTempFilterIndexByColumn(columnIndex);
            if (index >= 0) {
                mTempFilters.set(index, new TableFilter<>(rule));
            } else {
                mTempFilters.add(new TableFilter<>(rule));
            }
        }
        // 更新过滤规则
        updateRowFilter();
    }

    /**
     * 根据列名获取列下标
     *
     * @param columnName 列名
     * @return 失败返回-1
     */
    private int findColumnIndexByName(String columnName) {
        for (int i = 0; i < getColumnNames().size(); i++) {
            String name = getColumnName(i);
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
        if (mTempFilters != null && !mTempFilters.isEmpty()) {
            for (TableFilter<AbstractTableModel> item : mTempFilters) {
                FilterRule rule = item.getRule();
                if (rule.getColumnIndex() == columnIndex) {
                    return rule;
                }
            }
        }
        return new FilterRule(columnIndex);
    }

    /**
     * 根据列下标，查找临时过滤的 FilterRule 实例的下标
     *
     * @param columnIndex 对应的列下标
     * @return 未找到返回一个新创建的 FilterRule 实例
     */
    private int getTempFilterIndexByColumn(int columnIndex) {
        if (mTempFilters != null && !mTempFilters.isEmpty()) {
            for (int i = 0; i < mTempFilters.size(); i++) {
                FilterRule rule = mTempFilters.get(i).getRule();
                if (rule.getColumnIndex() == columnIndex) {
                    return i;
                }
            }
        }
        return -1;
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
    }

    /**
     * 停止添加任务数据（任务停止时调用）
     */
    public void stopAddTaskData() {
        mTaskTableModel.stopAddTaskData();
    }

    /**
     * 获取扫描任务的数量
     */
    public int getTaskCount() {
        return mTaskTableModel.getRowCount();
    }

    /**
     * 清除临时过滤规则
     */
    private void clearTempFilter() {
        mTempFilters.clear();
        updateRowFilter();
    }

    /**
     * 刷新所有字段
     */
    public void refreshColumns() {
        if (mTaskTableModel == null) {
            return;
        }
        // 重新初始化列名列表
        initColumnNames();
        // 重新初始化排序器实例
        mTableRowSorter = new TableRowSorter<>(mTaskTableModel);
        updateRowFilter();
        setRowSorter(mTableRowSorter);
        mTaskTableModel.fireTableStructureChanged();
        initColorLevelSorter();
        initColumnWidth();
    }

    /**
     * 显示文本信息对话框
     *
     * @param title 对话框标题
     * @param text  文本内容
     */
    private static void showTextAreaDialog(String title, String text) {
        JPanel panel = new JPanel(new VLayout());
        panel.setPreferredSize(new Dimension(400, 150));
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        JScrollPane pane = new JScrollPane(area);
        panel.add(pane, "1w");
        UIHelper.showCustomDialog(title, new String[]{L.get("close")}, panel);
    }

    /**
     * 根据颜色名，获取颜色等级
     *
     * @param colorName 颜色名
     * @return 颜色等级
     */
    private static int getColorLevel(String colorName) {
        int level = FpManager.findColorLevelByName(colorName);
        return FpManager.sColorNames.length - level;
    }

    /**
     * 获取所有字段名
     *
     * @return 失败返回空列表
     */
    public static Vector<String> getColumnNames() {
        if (sColumnNames != null) {
            return sColumnNames;
        }
        initColumnNames();
        return sColumnNames;
    }

    /**
     * 初始化所有字段名
     */
    private static void initColumnNames() {
        Vector<String> result = new Vector<>(Arrays.asList(TaskTableModel.PRE_COLUMN_NAMES));
        // 指纹字段名列表
        List<String> fpColumnNames = FpManager.getColumnNames();
        result.addAll(fpColumnNames);
        sColumnNames = result;
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
         * 添加 Host 到黑名单
         *
         * @param hosts Host 列表
         */
        void addHostToBlocklist(ArrayList<String> hosts);
    }

    /**
     * 列表适配器
     */
    public static class TaskTableModel extends AbstractTableModel
            implements DataTableItemLoader.OnDataItemLoadEvent<TaskData> {

        /**
         * 预设的字段名
         */
        private static final String[] PRE_COLUMN_NAMES = new String[]{
                L.get("task_table_columns.id"),
                L.get("task_table_columns.from"),
                L.get("task_table_columns.method"),
                L.get("task_table_columns.host"),
                L.get("task_table_columns.url"),
                L.get("task_table_columns.title"),
                L.get("task_table_columns.ip"),
                L.get("task_table_columns.status"),
                L.get("task_table_columns.length"),
                L.get("task_table_columns.color"),
        };
        private final List<TaskData> mData;
        private final AtomicInteger mCounter;
        private final DataTableItemLoader<TaskData> mItemLoader;

        public TaskTableModel() {
            mData = Collections.synchronizedList(new ArrayList<>());
            mCounter = new AtomicInteger();
            mItemLoader = new DataTableItemLoader<>(this, 500);
        }

        public void add(TaskData data) {
            if (data == null || data.getReqResp() == null) {
                return;
            }
            int id = mCounter.getAndIncrement();
            data.setId(id);
            mItemLoader.pushItem(data);
        }

        public void addAll(List<TaskData> items) {
            if (items == null || items.isEmpty()) {
                return;
            }
            // 数据不允许为空
            List<TaskData> validItems = items.stream().filter(Objects::nonNull).collect(Collectors.toList());
            if (validItems.isEmpty()) {
                return;
            }
            synchronized (this) {
                int firstRow = getRowCount();
                mData.addAll(validItems);
                int lastRow = getRowCount() - 1;
                if (firstRow > 0) {
                    fireTableRowsInserted(firstRow, lastRow);
                } else {
                    fireTableDataChanged();
                }
            }
        }

        public synchronized void removeItems(List<TaskData> list) {
            if (list == null || list.isEmpty()) {
                return;
            }
            mData.removeAll(list);
            fireTableDataChanged();
        }

        public synchronized void clearAll() {
            mData.clear();
            fireTableDataChanged();
        }

        @Override
        public synchronized int getRowCount() {
            return mData.size();
        }

        @Override
        public int getColumnCount() {
            return getColumnNames().size();
        }

        @Override
        public String getColumnName(int column) {
            return getColumnNames().get(column);
        }

        private synchronized TaskData getItemData(int rowIndex) {
            if (rowIndex < 0 || rowIndex >= getRowCount()) {
                return null;
            }
            return mData.get(rowIndex);
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TaskData data = getItemData(rowIndex);
            if (data == null) {
                return "";
            }
            // 预设列的数据
            if (columnIndex >= 0 && columnIndex < PRE_COLUMN_NAMES.length) {
                return ClassUtils.getValueByFieldId(data, columnIndex);
            }
            // 减去预设列的数据，开始填充指纹参数里的数据
            columnIndex = columnIndex - PRE_COLUMN_NAMES.length;
            Map<String, String> params = data.getParams();
            String key = FpManager.getColumnId(columnIndex);
            if (key != null && params.containsKey(key)) {
                return params.get(key);
            }
            return "";
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex >= 0 && columnIndex < PRE_COLUMN_NAMES.length) {
                return ClassUtils.getTypeByFieldId(TaskData.class, columnIndex);
            }
            return String.class;
        }

        @Override
        public void onDataItemLoaded(List<TaskData> items) {
            addAll(items);
        }

        public void stopAddTaskData() {
            // 任务停止后。取出所有队列数据，添加到列表
            mItemLoader.flush();
        }
    }
}
