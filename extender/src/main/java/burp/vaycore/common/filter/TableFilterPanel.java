package burp.vaycore.common.filter;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;

/**
 * 表过滤面板
 * <p>
 * Created by vaycore on 2023-02-27.
 */
public class TableFilterPanel extends JPanel implements ItemListener, ActionListener {

    private JComboBox<String> mColumnList;
    private JPanel mRulesPanel;

    private final ArrayList<FilterRule> mRules;
    private int mLastColumnIndex = 0;
    private final String[] mColumns;
    private JScrollPane mRulesScrollPanel;

    public TableFilterPanel(String[] columns, ArrayList<FilterRule> rules) {
        if (columns == null) {
            throw new IllegalArgumentException("columns param is null.");
        }
        if (rules == null) {
            rules = new ArrayList<>();
        }
        mRules = rules;
        mColumns = columns;
        initView();
        setupData();
    }

    private void initView() {
        setPreferredSize(new Dimension(450, 260));
        setLayout(new VLayout(10));
        // 选择过滤字段，添加、清除字段过滤规则
        JPanel columnPanel = new JPanel();
        add(columnPanel);
        columnPanel.setLayout(new HLayout(10, true));
        JLabel filterLabel = new JLabel("Select column:");
        columnPanel.add(filterLabel);
        mColumnList = new JComboBox<>(mColumns);
        mColumnList.setSelectedIndex(mLastColumnIndex);
        mColumnList.addItemListener(this);
        columnPanel.add(mColumnList,"20%");
        columnPanel.add(new JPanel(), "1w");
        // 添加过滤
        JButton addItemBtn = new JButton("Add filter");
        addItemBtn.setToolTipText("Add filter");
        addItemBtn.setActionCommand("add-filter-item");
        addItemBtn.addActionListener(this);
        columnPanel.add(addItemBtn, "20%");
        // 清除过滤
        JButton clearBtn = new JButton("Clear");
        clearBtn.setToolTipText("Clear");
        clearBtn.setActionCommand("clear-filter-item");
        clearBtn.addActionListener(this);
        columnPanel.add(clearBtn, "15%");
        // 规则设置
        mRulesScrollPanel = new JScrollPane();
        mRulesScrollPanel.getVerticalScrollBar().setUnitIncrement(30);
        add(mRulesScrollPanel, "1w");
        mRulesPanel = new JPanel();
        mRulesScrollPanel.setViewportView(mRulesPanel);
        mRulesPanel.setLayout(new VFlowLayout());
    }

    private void setupData() {
        mRulesPanel.removeAll();
        int index = indexOfByColumnIndex(mLastColumnIndex);
        // 如果不存在规则配置
        if (index == -1) {
            // 添加默认显示的UI
            addRuleItem(0, 0, null);
        } else {
            FilterRule rule = mRules.get(index);
            ArrayList<FilterRule.Item> items = rule.getItems();
            // 遍历添加数据
            for (FilterRule.Item item : items) {
                addRuleItem(item.getLogic(), item.getOperate(), item.getValue());
            }
        }
        UIHelper.refreshUI(mRulesScrollPanel);
    }

    private void addRuleItem(int logic, int operate, String value) {
        JPanel panel = new JPanel();
        mRulesPanel.add(panel);
        panel.setLayout(new VLayout());
        if (logic == 0) {
            panel.setPreferredSize(new Dimension(0, 31));
        } else {
            panel.setPreferredSize(new Dimension(0, 62));
        }
        // 过滤规则 AND、OR 选项
        JPanel radioBtnPanel = new JPanel();
        radioBtnPanel.setBorder(new EmptyBorder(0, 5, 0, 0));
        panel.add(radioBtnPanel);
        radioBtnPanel.setLayout(new HLayout(10));
        JRadioButton andRadioBtn = new JRadioButton("AND");
        andRadioBtn.setFocusable(false);
        andRadioBtn.setSelected(logic == FilterRule.LOGIC_AND);
        JRadioButton orRadioBtn = new JRadioButton("OR");
        orRadioBtn.setFocusable(false);
        orRadioBtn.setSelected(logic == FilterRule.LOGIC_OR);
        UIHelper.createRadioGroup(andRadioBtn, orRadioBtn);
        radioBtnPanel.add(andRadioBtn);
        radioBtnPanel.add(orRadioBtn);
        radioBtnPanel.setVisible(logic > 0);
        // 过滤规则条件
        JPanel rulePanel = new JPanel();
        panel.add(rulePanel);
        rulePanel.setLayout(new HLayout(5, true));
        JComboBox<String> operateBox = new JComboBox<>(FilterRule.OPERATE_ITEMS);
        operateBox.setSelectedIndex(operate);
        rulePanel.add(operateBox);
        JTextField input = new JTextField(value);
        rulePanel.add(input, "1w");
        JButton delBtn = new JButton("X");
        rulePanel.add(delBtn, "40px");
        delBtn.setEnabled(logic > 0);
        delBtn.addActionListener(e -> {
            mRulesPanel.remove(panel);
            UIHelper.refreshUI(mRulesScrollPanel);
        });
    }

    @Override
    public void itemStateChanged(ItemEvent e) {
        if (mColumnList == null) {
            return;
        }
        int index = mColumnList.getSelectedIndex();
        if (mLastColumnIndex == index) {
            return;
        }
        // 切换前先保存数据
        saveColumnRuleItem(mLastColumnIndex);
        mLastColumnIndex = index;
        // 切换后刷新页面数据
        setupData();
    }

    private void saveColumnRuleItem(int lastColumnIndex) {
        int index = indexOfByColumnIndex(lastColumnIndex);
        FilterRule rule = new FilterRule(lastColumnIndex);
        int ruleCount = mRulesPanel.getComponentCount();
        // 遍历组件数据，填充到对象
        for (int i = 0; i < ruleCount; i++) {
            JPanel panel = (JPanel) mRulesPanel.getComponent(i);
            // 获取逻辑运算符
            int logic = 0;
            JPanel radioBtnPanel = (JPanel) panel.getComponent(0);
            if (radioBtnPanel.isVisible()) {
                JRadioButton andRadioBtn = (JRadioButton) radioBtnPanel.getComponent(0);
                logic = andRadioBtn.isSelected() ? FilterRule.LOGIC_AND : FilterRule.LOGIC_OR;
            }
            // 获取操作符
            JPanel rulePanel = (JPanel) panel.getComponent(1);
            JComboBox<String> operateBox = (JComboBox<String>) rulePanel.getComponent(0);
            int operate = operateBox.getSelectedIndex();
            // 获取值
            JTextField input = (JTextField) rulePanel.getComponent(1);
            String value = input.getText();
            try {
                rule.addRule(logic, operate, value);
            } catch (Exception e) {
                // 如果添加规则失败，舍弃该规则
            }
        }
        // 如果存在规则，将规则保存到内存
        if (rule.getItems().size() > 0) {
            if (index >= 0) {
                mRules.set(index, rule);
            } else {
                mRules.add(rule);
            }
        }
    }

    /**
     * 获取规则配置在列表中的下标
     *
     * @param columnIndex 规则配置下标
     * @return 返回规则配置所在的下标，不存在返回-1
     */
    private int indexOfByColumnIndex(int columnIndex) {
        if (mRules.isEmpty()) {
            return -1;
        }
        for (int i = 0; i < mRules.size(); i++) {
            FilterRule rule = mRules.get(i);
            if (rule.getColumnIndex() == columnIndex) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 导出过滤规则
     *
     * @return 过滤规则数据
     */
    public ArrayList<FilterRule> exportRules() {
        // 导出前保存一下当前数据
        saveColumnRuleItem(mLastColumnIndex);
        return mRules;
    }

    /**
     * 导出过滤规则表达式
     *
     * @return 返回过滤规则表达式
     */
    public String exportRulesText() {
        StringBuilder result = new StringBuilder();
        if (mRules == null || mRules.isEmpty()) {
            return result.toString();
        }
        for (FilterRule rule : mRules) {
            int columnIndex = rule.getColumnIndex();
            String columnName = mColumns[columnIndex];
            ArrayList<FilterRule.Item> items = rule.getItems();
            // 规则与规则之间是并且的关系
            if (!StringUtils.isEmpty(result)) {
                result.append(" && ");
            }
            for (FilterRule.Item item : items) {
                int logic = item.getLogic();
                int operate = item.getOperate();
                String value = item.getValue();
                if (logic > 0) {
                    result.append(logic == FilterRule.LOGIC_AND ? " && " : " || ");
                }
                result.append(columnName);
                String operateStr = FilterRule.OPERATE_CHAR[operate];
                // 拼接操作符，区分运算符和方法处理
                if (operate < FilterRule.OPERATE_START) {
                    // 处理一下空串和非数字的显示格式
                    if (StringUtils.isEmpty(value)) {
                        value = "''";
                    } else {
                        if (!StringUtils.isNumeric(value)) {
                            value = "'" + value + "'";
                        }
                    }
                    result.append(" ").append(operateStr).append(" ");
                    result.append(value);
                } else {
                    value = "'" + value + "'";
                    result.append(".").append(operateStr).append("(");
                    result.append(value).append(")");
                }
            }
        }
        return result.toString();
    }

    /**
     * 导出为表过滤器规则
     *
     * @return 表过滤器规则数据
     */
    public ArrayList<TableFilter<AbstractTableModel>> exportTableFilters() {
        ArrayList<TableFilter<AbstractTableModel>> filters = new ArrayList<>();
        for (FilterRule rule : mRules) {
            TableFilter<AbstractTableModel> filter = new TableFilter<>(rule);
            filters.add(filter);
        }
        return filters;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "add-filter-item":
                // 规则添加事件
                addRuleItem(1, 0, null);
                UIHelper.refreshUI(mRulesScrollPanel);
                break;
            case "clear-filter-item":
                // 规则清除事件
                int ruleIndex = indexOfByColumnIndex(mLastColumnIndex);
                if (ruleIndex != -1) {
                    mRules.remove(ruleIndex);
                }
                // 刷新
                setupData();
                break;
        }
    }

    /**
     * 显示设置对话框
     *
     * @param callback 对话框回调接口
     */
    public void showDialog(DialogCallback callback) {
        int state = UIHelper.showCustomDialog("Setup filter", new String[]{"OK", "Cancel", "Reset"}, this);
        if (state == JOptionPane.YES_OPTION) {
            ArrayList<FilterRule> filterRules = exportRules();
            ArrayList<TableFilter<AbstractTableModel>> filters = exportTableFilters();
            String rulesText = exportRulesText();
            if (callback != null) {
                callback.onConfirm(filterRules, filters, rulesText);
            }
        } else if (callback != null) {
            if (state == 2) {
                callback.onReset();
            } else {
                callback.onCancel();
            }
        }
    }

    public interface DialogCallback {

        /**
         * 点击 Ok 按钮回调
         *
         * @param filterRules 过滤规则
         * @param filters     处理成Swing直接使用的过滤规则
         * @param rulesText   规则表达式
         */
        void onConfirm(ArrayList<FilterRule> filterRules,
                       ArrayList<TableFilter<AbstractTableModel>> filters,
                       String rulesText);

        /**
         * 点击 Reset 按钮回调
         */
        void onReset();

        /**
         * 点击 Cancel 按钮回调
         */
        void onCancel();
    }
}
