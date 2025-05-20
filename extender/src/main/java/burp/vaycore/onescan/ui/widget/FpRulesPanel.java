package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.onescan.bean.FpRule;
import burp.vaycore.onescan.common.L;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * 指纹规则详情
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpRulesPanel extends JPanel {

    private JScrollPane mRulesScrollPanel;
    private JPanel mRulesPanel;
    private Vector<String> mMethodItems;
    private Vector<String> mMatchItems;

    public FpRulesPanel() {
        this(null);
    }

    public FpRulesPanel(ArrayList<FpRule> rules) {
        if (rules == null) {
            rules = new ArrayList<>();
        } else {
            rules = ClassUtils.deepCopy(rules);
        }
        initView();
        setupData(rules);
    }

    private void initView() {
        setPreferredSize(new Dimension(600, 300));
        setLayout(new VLayout(10));
        JPanel columnPanel = new JPanel(new HLayout(10, true));
        add(columnPanel);
        JButton addItemBtn = new JButton(L.get("fingerprint_rules.add_rule"));
        addItemBtn.setActionCommand("add-rule-item");
        addItemBtn.addActionListener((e) -> {
            addRuleItem(null);
            UIHelper.refreshUI(mRulesScrollPanel);
        });
        columnPanel.add(addItemBtn);
        mRulesPanel = new JPanel(new VFlowLayout());
        mRulesScrollPanel = new JScrollPane(mRulesPanel);
        mRulesScrollPanel.getVerticalScrollBar().setUnitIncrement(30);
        add(mRulesScrollPanel, "1w");
    }

    private void setupData(ArrayList<FpRule> rules) {
        if (rules.isEmpty()) {
            return;
        }
        mRulesPanel.removeAll();
        for (FpRule rule : rules) {
            addRuleItem(rule);
        }
        UIHelper.refreshUI(mRulesScrollPanel);
    }

    private void addRuleItem(FpRule rule) {
        String dataSource = "";
        String field = "";
        String method = "";
        String content = "";
        if (rule != null) {
            dataSource = rule.getDataSource();
            field = rule.getField();
            method = rule.getMethod();
            content = rule.getContent();
        }
        // 布局
        JPanel panel = new JPanel(new HLayout(5, true));
        mRulesPanel.add(panel);
        // 数据源组件
        JComboBox<String> dataSourceBox = new JComboBox<>(genDataSourceItems());
        dataSourceBox.setSelectedItem(dataSource);
        panel.add(dataSourceBox);
        // 数据字段组件
        JComboBox<String> fieldBox = new JComboBox<>(genDataFieldItems(dataSource));
        fieldBox.setSelectedItem(field);
        panel.add(fieldBox);
        // 匹配方法组件
        JComboBox<String> methodBox = new JComboBox<>(genMethodItems());
        methodBox.setSelectedItem(method);
        panel.add(methodBox);
        // 输入框组件
        JTextField input = new JTextField(content);
        panel.add(input, "1w");
        // 删除按钮组件
        JButton delBtn = new JButton("X");
        panel.add(delBtn, "40px");
        // 事件处理
        delBtn.addActionListener((e) -> {
            mRulesPanel.remove(panel);
            UIHelper.refreshUI(mRulesScrollPanel);
        });
        dataSourceBox.addItemListener((e) -> {
            if (e.getStateChange() == ItemEvent.DESELECTED) {
                return;
            }
            String dataSourceItem = String.valueOf(e.getItem());
            Vector<String> items = genDataFieldItems(dataSourceItem);
            fieldBox.setModel(new DefaultComboBoxModel<>(items));
        });
    }

    private Vector<String> genDataSourceItems() {
        if (mMatchItems != null) {
            return mMatchItems;
        }
        Vector<String> result = new Vector<>();
        result.add(L.get("fingerprint_rules.data_source"));
        List<String> dataSources = FpRule.getDataSources();
        result.addAll(dataSources);
        mMatchItems = result;
        return result;
    }

    private Vector<String> genDataFieldItems(String dataSource) {
        Vector<String> result = new Vector<>();
        result.add(L.get("fingerprint_rules.data_field"));
        List<String> fields = FpRule.getFieldsByDataSource(dataSource);
        result.addAll(fields);
        return result;
    }

    private Vector<String> genMethodItems() {
        if (mMethodItems != null) {
            return mMethodItems;
        } else {
            Vector<String> result = new Vector<>();
            result.add(L.get("fingerprint_rules.match_method"));
            List<String> methods = FpRule.getMethods();
            result.addAll(methods);
            mMethodItems = result;
            return result;
        }
    }

    private ArrayList<FpRule> exportRules() {
        ArrayList<FpRule> rules = new ArrayList<>();
        int ruleCount = mRulesPanel.getComponentCount();
        for (int i = 0; i < ruleCount; i++) {
            JPanel panel = (JPanel) mRulesPanel.getComponent(i);
            // 数据源
            JComboBox<String> dataSourceBox = (JComboBox) panel.getComponent(0);
            int dataSourceIndex = dataSourceBox.getSelectedIndex();
            // 数据字段
            JComboBox<String> fieldBox = (JComboBox) panel.getComponent(1);
            int fieldIndex = fieldBox.getSelectedIndex();
            // 匹配方法
            JComboBox<String> methodBox = (JComboBox) panel.getComponent(2);
            int methodIndex = methodBox.getSelectedIndex();
            JTextField input = (JTextField) panel.getComponent(3);
            if (dataSourceIndex == 0 || fieldIndex == 0 || methodIndex == 0) {
                continue;
            }
            String dataSource = genDataSourceItems().get(dataSourceIndex);
            String field = genDataFieldItems(dataSource).get(fieldIndex);
            String method = genMethodItems().get(methodIndex);
            String value = input.getText();
            FpRule rule = new FpRule();
            rule.setDataSource(dataSource);
            rule.setField(field);
            rule.setMethod(method);
            rule.setContent(value);
            rules.add(rule);
        }
        return rules;
    }

    public ArrayList<FpRule> showDialog(Component parentComponent) {
        int state = UIHelper.showCustomDialog(L.get("fingerprint_rules.dialog_title"), this, parentComponent);
        if (state != JOptionPane.OK_OPTION) {
            return null;
        }
        ArrayList<FpRule> rules = exportRules();
        if (rules.isEmpty()) {
            UIHelper.showTipsDialog(L.get("fingerprint_rules.empty_hint"), parentComponent);
            return showDialog(parentComponent);
        }
        return rules;
    }
}
