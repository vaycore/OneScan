package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.FpRule;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.NumberFilter;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

/**
 * 指纹详情
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpDetailPanel extends JPanel implements ActionListener {

    private boolean hasCreate;
    private final FpData mData;
    private JTextField mName;
    private JTextField mCompany;
    private JTextField mLang;
    private JTextField mSoftHard;
    private JTextField mFrame;
    private JTextField mParentCategory;
    private JTextField mCategory;
    private DefaultListModel<String> mRulesListModel;
    private JList<String> mRulesListView;

    public FpDetailPanel() {
        this(null);
    }

    public FpDetailPanel(FpData data) {
        this.hasCreate = false;
        if (data == null) {
            data = new FpData();
            this.hasCreate = true;
        } else {
            data = ClassUtils.deepCopy(data);
        }
        mData = data;
        this.initView();
        this.setupData();
    }

    private void initView() {
        this.setPreferredSize(new Dimension(400, 450));
        this.setLayout(new VLayout());
        this.addInputPanel();
        this.addRulesPanel();
    }

    private void setupData() {
        if (this.hasCreate) {
            return;
        }
        mName.setText(mData.getName());
        mCompany.setText(mData.getCompany());
        mLang.setText(mData.getLang());
        mSoftHard.setText(mData.getSoftHard());
        mFrame.setText(mData.getFrame());
        mParentCategory.setText(mData.getParentCategory());
        mCategory.setText(mData.getCategory());
        ArrayList<ArrayList<FpRule>> rules = mData.getRules();
        for (ArrayList<FpRule> fpRules : rules) {
            String ruleItem = this.parseFpRulesToStr(fpRules);
            mRulesListModel.addElement(ruleItem);
        }
    }

    private void addInputPanel() {
        mName = this.addInputItem(L.get("fingerprint_table_columns.name"));
        mCompany = this.addInputItem(L.get("fingerprint_table_columns.company"));
        mLang = this.addInputItem(L.get("fingerprint_table_columns.lang"));
        mSoftHard = this.addInputItem(L.get("fingerprint_table_columns.soft_hard"));
        mSoftHard.addKeyListener(new NumberFilter());
        mFrame = this.addInputItem(L.get("fingerprint_table_columns.frame"));
        mParentCategory = this.addInputItem(L.get("fingerprint_table_columns.parent_category"));
        mCategory = this.addInputItem(L.get("fingerprint_table_columns.category"));
    }

    private JTextField addInputItem(String label) {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(2, true));
        panel.add(new JLabel(label + "："), "105px");
        JTextField textField = new JTextField(25);
        panel.add(textField);
        this.add(panel);
        return textField;
    }

    private void addRulesPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(5));
        panel.setBorder(new TitledBorder(L.get("fingerprint_detail.rules_border_title")));
        panel.add(this.addLeftPanel(), "75px");
        mRulesListModel = new DefaultListModel<>();
        mRulesListView = new JList<>(mRulesListModel);
        UIHelper.setListCellRenderer(mRulesListView);
        JScrollPane scrollPane = new JScrollPane(mRulesListView);
        panel.add(scrollPane, "1w");
        this.add(panel, "1w");
    }

    private JPanel addLeftPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new VLayout(5));
        this.addButton(panel, L.get("add"), "add-item");
        this.addButton(panel, L.get("edit"), "edit-item");
        this.addButton(panel, L.get("delete"), "delete-item");
        this.addButton(panel, L.get("up"), "up-item");
        this.addButton(panel, L.get("down"), "down-item");
        return panel;
    }

    private void addButton(JPanel panel, String text, String actionCommand) {
        JButton btn = new JButton(text);
        btn.setActionCommand(actionCommand);
        btn.addActionListener(this);
        panel.add(btn);
    }

    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        ArrayList<ArrayList<FpRule>> rules = mData.getRules();
        if (rules == null) {
            rules = new ArrayList<>();
            mData.setRules(rules);
        }

        if ("add-item".equals(action)) {
            FpRulesPanel panel = new FpRulesPanel();
            ArrayList<FpRule> fpRules = panel.showDialog(this);
            if (fpRules != null) {
                rules.add(fpRules);
                String rulesText = this.parseFpRulesToStr(fpRules);
                mRulesListModel.addElement(rulesText);
            }
        }
        int index = mRulesListView.getSelectedIndex();
        if (index < 0 || index >= rules.size()) {
            return;
        }
        switch (action) {
            case "edit-item":
                FpRulesPanel panel = new FpRulesPanel(rules.get(index));
                ArrayList<FpRule> fpRules = panel.showDialog(this);
                if (fpRules != null) {
                    rules.set(index, fpRules);
                    String rulesText = this.parseFpRulesToStr(fpRules);
                    mRulesListModel.setElementAt(rulesText, index);
                }
                break;
            case "delete-item":
                int ret = UIHelper.showOkCancelDialog(L.get("fingerprint_detail.confirm_delete_rule_hint"), this);
                if (ret == 0) {
                    mRulesListModel.removeElementAt(index);
                    rules.remove(index);
                }
                break;
            case "up-item":
                int upIndex = index - 1;
                if (upIndex >= 0) {
                    String temp = mRulesListModel.get(upIndex);
                    mRulesListModel.setElementAt(mRulesListModel.get(index), upIndex);
                    mRulesListModel.setElementAt(temp, index);
                    mRulesListView.setSelectedIndex(upIndex);
                    ArrayList<FpRule> tempRule = rules.get(upIndex);
                    rules.set(upIndex, rules.get(index));
                    rules.set(index, tempRule);
                }
                break;
            case "down-item":
                int downIndex = index + 1;
                if (downIndex < mRulesListModel.size()) {
                    String temp = mRulesListModel.get(index);
                    mRulesListModel.setElementAt(mRulesListModel.get(downIndex), index);
                    mRulesListModel.setElementAt(temp, downIndex);
                    mRulesListView.setSelectedIndex(downIndex);
                    ArrayList<FpRule> tempRule = rules.get(index);
                    rules.set(index, rules.get(downIndex));
                    rules.set(downIndex, tempRule);
                }
                break;
        }
    }

    private String parseFpRulesToStr(ArrayList<FpRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return "";
        }
        ArrayList<String> ruleItems = new ArrayList<>();
        for (FpRule rule : rules) {
            String content = rule.getContent().replace("\"", "\\\"");
            String sb = rule.getMatch() + "." + rule.getMethod() + "(\"" + content + "\")";
            ruleItems.add(sb);
        }
        return StringUtils.join(ruleItems, " && ");
    }

    public FpData showDialog() {
        int state = UIHelper.showCustomDialog(L.get("fingerprint_detail.dialog_title"), this);
        if (state != JOptionPane.OK_OPTION) {
            return null;
        }
        String name = mName.getText();
        String company = mCompany.getText();
        String lang = mLang.getText();
        String softHard = mSoftHard.getText();
        String frame = mFrame.getText();
        String parentCategory = mParentCategory.getText();
        String category = mCategory.getText();
        if (StringUtils.isEmpty(name)) {
            UIHelper.showTipsDialog(L.get("fingerprint_detail.name_empty_hint"));
            return this.showDialog();
        }
        if (mData.getRules() == null || mData.getRules().isEmpty()) {
            UIHelper.showTipsDialog(L.get("fingerprint_detail.rules_empty_hint"));
            return this.showDialog();
        }
        if (StringUtils.isEmpty(company)) {
            company = "Other";
        }
        if (StringUtils.isEmpty(softHard)) {
            softHard = "0";
        }
        if (StringUtils.isEmpty(parentCategory)) {
            parentCategory = "Other";
        }
        if (StringUtils.isEmpty(category)) {
            category = "Other";
        }
        mData.setName(name);
        mData.setCompany(company);
        mData.setLang(lang);
        mData.setSoftHard(softHard);
        mData.setFrame(frame);
        mData.setParentCategory(parentCategory);
        mData.setCategory(category);
        return mData;
    }
}
