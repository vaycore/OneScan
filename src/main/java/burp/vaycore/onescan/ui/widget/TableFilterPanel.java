package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.onescan.bean.FilterRule;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
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
        // 选择过滤字段、重置
        JPanel columnPanel = new JPanel();
        add(columnPanel);
        columnPanel.setLayout(new HLayout(10, true));
        JLabel filterLabel = new JLabel("Select column:");
        columnPanel.add(filterLabel);
        mColumnList = new JComboBox<>(mColumns);
        mColumnList.setSelectedIndex(mLastColumnIndex);
        mColumnList.addItemListener(this);
        columnPanel.add(mColumnList);
        columnPanel.add(new JPanel(), "1w");
        JButton addItemBtn = new JButton("Add filter");
        addItemBtn.setActionCommand("add-filter-item");
        addItemBtn.addActionListener(this);
        columnPanel.add(addItemBtn);
        JButton clearBtn = new JButton("Clear");
        clearBtn.setActionCommand("clear-filter-item");
        clearBtn.addActionListener(this);
        columnPanel.add(clearBtn);
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
        JButton delBtn = new JButton("Del");
        rulePanel.add(delBtn);
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

    public ArrayList<FilterRule> exportRules() {
        ArrayList<FilterRule> result = new ArrayList<>();
        // 导出前保存一下当前数据
        saveColumnRuleItem(mLastColumnIndex);
        // 检测是否有数据
        if (mRules.isEmpty()) {
            return result;
        }
        // 导出数据
        result.addAll(mRules);
        return result;
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
}
