package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.onescan.bean.FpRule;
import burp.vaycore.onescan.common.FpMethodHandler;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
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
        JPanel columnPanel = new JPanel();
        add(columnPanel);
        columnPanel.setLayout(new HLayout(10, true));
        JButton addItemBtn = new JButton("Add Rule");
        addItemBtn.setActionCommand("add-rule-item");
        addItemBtn.addActionListener((e) -> {
            addRuleItem(null);
            UIHelper.refreshUI(mRulesScrollPanel);
        });
        columnPanel.add(addItemBtn);
        mRulesScrollPanel = new JScrollPane();
        mRulesScrollPanel.getVerticalScrollBar().setUnitIncrement(30);
        add(mRulesScrollPanel, "1w");
        mRulesPanel = new JPanel();
        mRulesScrollPanel.setViewportView(mRulesPanel);
        mRulesPanel.setLayout(new VFlowLayout());
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
        String match = "";
        String method = "";
        String content = "";
        if (rule != null) {
            match = rule.getMatch();
            method = rule.getMethod();
            content = rule.getContent();
        }

        JPanel panel = new JPanel();
        mRulesPanel.add(panel);
        panel.setLayout(new HLayout(5, true));
        JComboBox<String> matchBox = new JComboBox<>(genMatchItems());
        matchBox.setSelectedItem(match);
        panel.add(matchBox);
        JComboBox<String> methodBox = new JComboBox<>(genMethodItems());
        methodBox.setSelectedItem(method);
        panel.add(methodBox);
        JTextField input = new JTextField(content);
        panel.add(input, "1w");
        JButton delBtn = new JButton("X");
        panel.add(delBtn, "40px");
        delBtn.addActionListener((e) -> {
            mRulesPanel.remove(panel);
            UIHelper.refreshUI(mRulesScrollPanel);
        });
    }

    private Vector<String> genMatchItems() {
        if (mMatchItems != null) {
            return mMatchItems;
        }
        Field[] fields = FpRule.class.getDeclaredFields();
        Vector<String> result = new Vector<>();
        result.add("数据源");
        for (Field field : fields) {
            field.setAccessible(true);
            String name = field.getName();
            if (name.startsWith("MATCH_")) {
                try {
                    String value = (String) field.get(null);
                    result.add(value);
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            }
        }
        mMatchItems = result;
        return result;
    }

    private Vector<String> genMethodItems() {
        if (mMethodItems != null) {
            return mMethodItems;
        } else {
            Method[] methods = FpMethodHandler.class.getDeclaredMethods();
            Vector<String> result = new Vector<>();
            result.add("匹配方法");
            for (Method method : methods) {
                String name = method.getName();
                result.add(name);
            }
            mMethodItems = result;
            return result;
        }
    }

    private ArrayList<FpRule> exportRules() {
        ArrayList<FpRule> rules = new ArrayList<>();
        int ruleCount = mRulesPanel.getComponentCount();
        for (int i = 0; i < ruleCount; i++) {
            JPanel panel = (JPanel) mRulesPanel.getComponent(i);
            JComboBox<String> matchBox = (JComboBox) panel.getComponent(0);
            int matchIndex = matchBox.getSelectedIndex();
            JComboBox<String> methodBox = (JComboBox) panel.getComponent(1);
            int methodIndex = methodBox.getSelectedIndex();
            JTextField input = (JTextField) panel.getComponent(2);
            if (matchIndex == 0 || methodIndex == 0) {
                continue;
            }
            String match = genMatchItems().get(matchIndex);
            String method = genMethodItems().get(methodIndex);
            String value = input.getText();
            FpRule rule = new FpRule();
            rule.setMatch(match);
            rule.setMethod(method);
            rule.setContent(value);
            rules.add(rule);
        }
        return rules;
    }

    public ArrayList<FpRule> showDialog(Component parentComponent) {
        int state = UIHelper.showCustomDialog("Setup Rules", this, parentComponent);
        if (state != JOptionPane.OK_OPTION) {
            return null;
        }
        ArrayList<FpRule> rules = exportRules();
        if (rules.isEmpty()) {
            UIHelper.showTipsDialog("Rules is empty.", parentComponent);
            return showDialog(parentComponent);
        }
        return rules;
    }
}
