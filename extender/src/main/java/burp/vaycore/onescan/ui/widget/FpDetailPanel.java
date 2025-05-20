package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.FpRule;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * 指纹详情
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpDetailPanel extends JPanel implements ActionListener {

    private final boolean hasCreate;
    private final FpData mData;
    private JComboBox<String> mColorComboBox;
    private DefaultListModel<String> mRulesListModel;
    private JList<String> mRulesListView;
    private JPanel mParamsPanel;
    private JScrollPane mParamsScrollPanel;
    private Vector<String> mParamNameItems;

    public FpDetailPanel() {
        this(null);
    }

    public FpDetailPanel(FpData data) {
        if (data == null) {
            data = new FpData();
            this.hasCreate = true;
        } else {
            data = ClassUtils.deepCopy(data);
            this.hasCreate = false;
        }
        mData = data;
        this.initView();
        this.setupData();
    }

    private void initView() {
        setLayout(new VLayout(3));
        setPreferredSize(new Dimension(400, 450));
        addParamsPanel();
        addColorPanel();
        addRulesPanel();
    }

    private void setupData() {
        if (this.hasCreate) {
            return;
        }
        // 指纹参数填充
        ArrayList<FpData.Param> params = mData.getParams();
        if (params != null) {
            for (FpData.Param param : params) {
                addParamItem(param);
            }
        }
        // 填充颜色数据
        mColorComboBox.setSelectedItem(mData.getColor());
        // 填充指纹规则
        ArrayList<ArrayList<FpRule>> rules = mData.getRules();
        for (ArrayList<FpRule> fpRules : rules) {
            String ruleItem = this.parseFpRulesToStr(fpRules);
            mRulesListModel.addElement(ruleItem);
        }
    }

    /**
     * 添加指纹参数布局
     */
    private void addParamsPanel() {
        // 添加参数按钮
        JButton addParamBtn = new JButton(L.get("fingerprint_detail.add_param"));
        addParamBtn.setActionCommand("add-param");
        addParamBtn.addActionListener(this);
        add(addParamBtn, "w-auto");
        // 参数列表
        mParamsPanel = new JPanel(new VFlowLayout());
        mParamsScrollPanel = new JScrollPane(mParamsPanel);
        mParamsScrollPanel.getVerticalScrollBar().setUnitIncrement(30);
        add(mParamsScrollPanel, "1w");
    }

    /**
     * 添加参数
     */
    private void doAddParam() {
        addParamItem(null);
        UIHelper.refreshUI(mParamsScrollPanel);
    }

    private void addParamItem(FpData.Param param) {
        String paramName = "";
        String paramValue = "";
        if (param != null) {
            // 存储的是指纹字段 ID 值，需要转换
            paramName = FpManager.findColumnNameById(param.getK());
            paramValue = param.getV();
        }
        // 布局
        JPanel panel = new JPanel(new HLayout(5, true));
        mParamsPanel.add(panel);
        // 参数名组件
        JComboBox<String> paramNameBox = new JComboBox<>(genParamNameItems());
        paramNameBox.setSelectedItem(paramName);
        panel.add(paramNameBox);
        // 参数值输入框组件
        HintTextField paramValueInput = new HintTextField(paramValue);
        paramValueInput.setHintText(L.get("fingerprint_detail.param_value"));
        panel.add(paramValueInput, "1w");
        // 删除按钮组件
        JButton delBtn = new JButton("X");
        panel.add(delBtn, "40px");
        // 事件处理
        delBtn.addActionListener((e) -> {
            mParamsPanel.remove(panel);
            UIHelper.refreshUI(mParamsScrollPanel);
        });
    }

    /**
     * 生成参数名 Item 选项
     */
    private Vector<String> genParamNameItems() {
        if (mParamNameItems != null) {
            return mParamNameItems;
        }
        Vector<String> result = new Vector<>();
        result.add(L.get("fingerprint_detail.param_name"));
        List<String> list = FpManager.getColumnNames();
        result.addAll(list);
        mParamNameItems = result;
        return result;
    }

    /**
     * 添加指纹颜色布局
     */
    private void addColorPanel() {
        String label = L.get("fingerprint_table_columns.color");
        JPanel panel = new JPanel(new HLayout(2, true));
        panel.add(new JLabel(label + "："), "78px");
        mColorComboBox = new JComboBox<>(FpManager.sColorNames);
        panel.add(mColorComboBox, "1w");
        add(panel);
    }

    /**
     * 添加指纹规则布局
     */
    private void addRulesPanel() {
        add(new JLabel(L.get("fingerprint_detail.rules_border_title")));
        // 指纹规则
        JPanel panel = new JPanel(new HLayout(5));
        panel.add(createRulesLeftPanel(), "75px");
        mRulesListModel = new DefaultListModel<>();
        mRulesListView = new JList<>(mRulesListModel);
        UIHelper.setListCellRenderer(mRulesListView);
        JScrollPane scrollPane = new JScrollPane(mRulesListView);
        panel.add(scrollPane, "1w");
        add(panel, "1w");
    }

    /**
     * 创建指纹规则功能按钮布局
     */
    private JPanel createRulesLeftPanel() {
        JPanel panel = new JPanel(new VLayout(5));
        addRulesLeftButton(panel, L.get("add"), "add-item");
        addRulesLeftButton(panel, L.get("edit"), "edit-item");
        addRulesLeftButton(panel, L.get("delete"), "delete-item");
        addRulesLeftButton(panel, L.get("up"), "up-item");
        addRulesLeftButton(panel, L.get("down"), "down-item");
        return panel;
    }

    /**
     * 添加指纹规则功能按钮
     */
    private void addRulesLeftButton(JPanel panel, String text, String action) {
        JButton btn = new JButton(text);
        btn.setActionCommand(action);
        btn.addActionListener(this);
        panel.add(btn);
    }

    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        ArrayList<ArrayList<FpRule>> rules = mData.getRules();
        if ("add-item".equals(action)) {
            FpRulesPanel panel = new FpRulesPanel();
            ArrayList<FpRule> fpRules = panel.showDialog(this);
            if (fpRules != null) {
                rules.add(fpRules);
                String rulesText = this.parseFpRulesToStr(fpRules);
                mRulesListModel.addElement(rulesText);
            }
            return;
        } else if ("add-param".equals(action)) {
            doAddParam();
            return;
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
                int ret = UIHelper.showOkCancelDialog(
                        L.get("fingerprint_detail.confirm_delete_rule_hint"), this);
                if (ret == 0) {
                    mRulesListModel.removeElementAt(index);
                    rules.remove(index);
                }
                break;
            case "up-item":
                int upIndex = index - 1;
                if (upIndex >= 0) {
                    doMoveItem(rules, index, upIndex);
                }
                break;
            case "down-item":
                int downIndex = index + 1;
                if (downIndex < mRulesListModel.size()) {
                    doMoveItem(rules, index, downIndex);
                }
                break;
        }
    }

    /**
     * 移动 Item 位置
     *
     * @param rules   指纹规则列表
     * @param index   当前位置下标
     * @param toIndex 目标位置下标
     */
    private void doMoveItem(ArrayList<ArrayList<FpRule>> rules, int index, int toIndex) {
        String temp = mRulesListModel.get(index);
        mRulesListModel.setElementAt(mRulesListModel.get(toIndex), index);
        mRulesListModel.setElementAt(temp, toIndex);
        mRulesListView.setSelectedIndex(toIndex);
        // 同步更新
        ArrayList<FpRule> tempRule = rules.get(index);
        rules.set(index, rules.get(toIndex));
        rules.set(toIndex, tempRule);
    }

    /**
     * 解析指纹规则数据，转换为表达式格式
     *
     * @param rules 指纹规则数据
     * @return 失败返回空字符串
     */
    private String parseFpRulesToStr(ArrayList<FpRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return "";
        }
        ArrayList<String> ruleItems = new ArrayList<>();
        for (FpRule rule : rules) {
            String content = rule.getContent().replace("\"", "\\\"");
            String sb = rule.getDataSource() + "." + rule.getField() + "." + rule.getMethod() + "(\"" + content + "\")";
            ruleItems.add(sb);
        }
        return StringUtils.join(ruleItems, " && ");
    }

    /**
     * 检测指纹参数列表是否已包含指纹字段 ID 值
     *
     * @param params   指纹参数列表
     * @param columnId 指纹字段 ID 值
     * @return true=包含；false=不包含
     */
    private boolean containsColumnId(ArrayList<FpData.Param> params, String columnId) {
        if (StringUtils.isEmpty(columnId) || params == null || params.isEmpty()) {
            return false;
        }
        for (FpData.Param param : params) {
            if (param != null && columnId.equals(param.getK())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取对话框标题
     */
    private String getDialogTitle() {
        if (hasCreate) {
            return L.get("fingerprint_detail.add_title");
        } else {
            return L.get("fingerprint_detail.edit_title");
        }
    }

    /**
     * 显示添加/编辑指纹对话框
     *
     * @return 返回添加/编辑完成的指纹数据实例；取消添加/编辑时返回null
     */
    public FpData showDialog() {
        int state = UIHelper.showCustomDialog(getDialogTitle(), this);
        if (state != JOptionPane.OK_OPTION) {
            return null;
        }
        // 获取用户输入的指纹参数信息
        int count = mParamsPanel.getComponentCount();
        ArrayList<FpData.Param> params = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            JPanel panel = (JPanel) mParamsPanel.getComponent(i);
            // 参数名组件
            JComboBox<String> paramNameBox = (JComboBox) panel.getComponent(0);
            int paramNameIndex = paramNameBox.getSelectedIndex();
            // 参数值输入框组件
            JTextField paramValueInput = (JTextField) panel.getComponent(1);
            if (paramNameIndex == 0) {
                continue;
            }
            String paramName = genParamNameItems().get(paramNameIndex);
            String columnId = FpManager.findColumnIdByName(paramName);
            // 找不到字段 ID 值（可能已经被删除）
            if (columnId == null) {
                continue;
            }
            String paramValue = paramValueInput.getText();
            // 参数值为空，忽略
            if (StringUtils.isEmpty(paramValue)) {
                continue;
            }
            // 检测是否添加重复参数
            if (containsColumnId(params, columnId)) {
                String message = L.get("fingerprint_detail.duplicate_param_names_exist", paramName);
                UIHelper.showTipsDialog(message, this);
                return showDialog();
            }
            params.add(new FpData.Param(columnId, paramValue));
        }
        // 设置指纹参数
        mData.setParams(params);
        // 设置指纹颜色
        String color = String.valueOf(mColorComboBox.getSelectedItem());
        mData.setColor(color);
        // 检测指纹规则是否为空
        if (mData.getRules().isEmpty()) {
            String message = L.get("fingerprint_detail.rules_empty_hint");
            UIHelper.showTipsDialog(message, this);
            return showDialog();
        }
        return mData;
    }
}
