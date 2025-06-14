package burp.vaycore.onescan.ui.tab;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.OnFpColumnModifyListener;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.ui.base.BaseTab;
import burp.vaycore.onescan.ui.widget.FpColumnManagerWindow;
import burp.vaycore.onescan.ui.widget.FpDetailPanel;
import burp.vaycore.onescan.ui.widget.FpTable;
import burp.vaycore.onescan.ui.widget.FpTestWindow;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

/**
 * 指纹面板
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FingerprintTab extends BaseTab implements ActionListener, KeyListener, OnFpColumnModifyListener {

    private FpTable mFpTable;
    private JLabel mCountLabel;
    private HintTextField mFpFilterRegexText;
    private FpTestWindow mFpTestWindow;
    private FpColumnManagerWindow mFpColumnManagerWindow;

    @Override
    protected void initData() {
        FpManager.addOnFpColumnModifyListener(this);
    }

    @Override
    protected void initView() {
        setLayout(new VLayout(0));
        initFpPathPanel();
        initTablePanel();
    }

    @Override
    public String getTitleName() {
        return L.get("tab_name.fingerprint");
    }

    private void initFpPathPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        panel.setBorder(new EmptyBorder(0, 5, 0, 5));
        // 指纹存放路径
        JTextField textField = new JTextField(FpManager.getPath(), 35);
        textField.setEditable(false);
        panel.add(textField);
        // 重新加载指纹
        JButton reload = new JButton(L.get("reload"));
        reload.setActionCommand("reload");
        reload.addActionListener(this);
        panel.add(reload);
        // 指纹数量展示
        panel.add(new JLabel(L.get("fingerprint_count")));
        mCountLabel = new JLabel(String.valueOf(FpManager.getCount()));
        panel.add(mCountLabel);
        panel.add(new JPanel(), "1w");
        // 指纹过滤功能
        mFpFilterRegexText = new HintTextField();
        mFpFilterRegexText.setHintText(L.get("regex_filter"));
        mFpFilterRegexText.addKeyListener(this);
        panel.add(mFpFilterRegexText, "1w");
        // 搜索按钮
        JButton search = new JButton(L.get("search"));
        search.setActionCommand("search");
        search.addActionListener(this);
        panel.add(search);
        add(panel, "35px");
    }

    private void initTablePanel() {
        JPanel panel = new JPanel(new VLayout(3));
        panel.setBorder(new EmptyBorder(0, 5, 5, 5));
        panel.add(addButtonPanel());
        mFpTable = new FpTable();
        JScrollPane scrollPane = new JScrollPane(mFpTable);
        scrollPane.setPreferredSize(new Dimension(scrollPane.getWidth(), 0));
        panel.add(scrollPane, "1w");
        add(panel, "1w");
    }

    private JPanel addButtonPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        addButton(panel, L.get("fingerprint_add"), "add-item");
        addButton(panel, L.get("fingerprint_edit"), "edit-item");
        addButton(panel, L.get("fingerprint_delete"), "delete-item");
        addButton(panel, L.get("fingerprint_test"), "test");
        addButton(panel, L.get("fingerprint_clear_cache"), "clear-cache");
        addButton(panel, L.get("fingerprint_column_manager"), "column-manager");
        return panel;
    }

    /**
     * 添加功能按钮
     *
     * @param panel         布局
     * @param text          按钮方案
     * @param actionCommand 事件名
     */
    private void addButton(JPanel panel, String text, String actionCommand) {
        JButton btn = new JButton(text);
        btn.setActionCommand(actionCommand);
        btn.addActionListener(this);
        panel.add(btn);
    }

    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {
        if (e.getKeyChar() == KeyEvent.VK_ENTER) {
            doSearch();
        }
    }

    @Override
    public void keyReleased(KeyEvent e) {
        String text = mFpFilterRegexText.getText();
        if (StringUtils.isEmpty(text)) {
            doSearch();
        }
    }

    @Override
    public void onFpColumnModify() {
        if (mFpTable != null) {
            mFpTable.refreshColumns();
        }
    }

    /**
     * 刷新指纹数量
     */
    private void refreshCount() {
        String count = String.valueOf(FpManager.getCount());
        mCountLabel.setText(count);
    }

    /**
     * 关闭指纹测试窗口
     */
    public void closeFpTestWindow() {
        if (mFpTestWindow != null) {
            mFpTestWindow.closeWindow();
        }
    }

    /**
     * 关闭指纹字段管理窗口
     */
    public void closeFpColumnManagerWindow() {
        if (mFpColumnManagerWindow != null) {
            mFpColumnManagerWindow.closeWindow();
        }
    }

    /**
     * 获取选中的真实数据下标
     *
     * @return 未选中返回-1
     */
    private int getSelectedRowIndex() {
        int rowIndex = mFpTable.getSelectedRow();
        if (rowIndex < 0 || rowIndex >= mFpTable.getRowCount()) {
            return -1;
        }
        return mFpTable.convertRowIndexToModel(rowIndex);
    }

    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        int rowIndex = getSelectedRowIndex();
        FpData data = mFpTable.getFpData(rowIndex);
        switch (action) {
            case "reload":
                doReload();
                break;
            case "search":
                doSearch();
                break;
            case "add-item":
                doAddItem();
                break;
            case "edit-item":
                doEditItem(data, rowIndex);
                break;
            case "delete-item":
                doDeleteItem(data, rowIndex);
                break;
            case "test":
                doTest();
                break;
            case "clear-cache":
                doClearCache();
                break;
            case "column-manager":
                doColumnManager();
                break;
        }
    }

    /**
     * 重新加载
     */
    private void doReload() {
        mFpTable.reloadData();
        refreshCount();
        UIHelper.showTipsDialog(L.get("reload_success"));
    }

    /**
     * 搜索
     */
    private void doSearch() {
        String regex = mFpFilterRegexText.getText();
        if (StringUtils.isEmpty(regex)) {
            mFpTable.setRowFilter(null);
        } else {
            mFpTable.setRowFilter(RowFilter.regexFilter(regex));
        }
    }

    /**
     * 添加指纹
     */
    private void doAddItem() {
        FpData addData = (new FpDetailPanel()).showDialog();
        if (addData != null) {
            mFpTable.addFpData(addData);
            refreshCount();
        }
    }

    /**
     * 编辑指纹
     *
     * @param data     指纹数据
     * @param rowIndex 下标
     */
    private void doEditItem(FpData data, int rowIndex) {
        if (data == null) {
            return;
        }
        FpData editData = new FpDetailPanel(data).showDialog();
        if (editData != null) {
            mFpTable.setFpData(rowIndex, editData);
        }
    }

    /**
     * 删除指纹
     *
     * @param data     指纹数据
     * @param rowIndex 下标
     */
    private void doDeleteItem(FpData data, int rowIndex) {
        if (data == null) {
            return;
        }
        String info = "{" + data.toInfo() + "}";
        int ret = UIHelper.showOkCancelDialog(L.get("fingerprint_delete_hint", info));
        if (ret == 0) {
            mFpTable.removeFpData(rowIndex);
            refreshCount();
        }
    }

    /**
     * 指纹测试
     */
    private void doTest() {
        if (mFpTestWindow == null) {
            mFpTestWindow = new FpTestWindow();
        }
        mFpTestWindow.showWindow();
    }

    /**
     * 清除缓存
     */
    private static void doClearCache() {
        int count = FpManager.getCacheCount();
        if (count == 0) {
            UIHelper.showTipsDialog(L.get("cache_is_empty"));
            return;
        }
        int ret = UIHelper.showOkCancelDialog(L.get("clear_cache_dialog_message", count));
        if (ret == 0) {
            FpManager.clearCache();
            UIHelper.showTipsDialog(L.get("clear_success"));
        }
    }

    /**
     * 字段管理
     */
    private void doColumnManager() {
        if (mFpColumnManagerWindow == null) {
            mFpColumnManagerWindow = new FpColumnManagerWindow();
        }
        mFpColumnManagerWindow.showWindow();
    }
}
