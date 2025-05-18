package burp.vaycore.onescan.ui.tab;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.ui.base.BaseTab;
import burp.vaycore.onescan.ui.widget.FpDetailPanel;
import burp.vaycore.onescan.ui.widget.FpTable;
import burp.vaycore.onescan.ui.widget.FpTestWindow;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

/**
 * 指纹面板
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FingerprintTab extends BaseTab implements ActionListener {
    private FpTable mFpTable;
    private JLabel mCountLabel;
    private HintTextField mFpFilterRegexText;
    private FpTestWindow mFpTestWindow;

    protected void initData() {

    }

    protected void initView() {
        setLayout(new VLayout());
        addFpPathPanel();
        addTablePanel();
    }

    private void addFpPathPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(5, true));
        panel.setBorder(new EmptyBorder(0, 5, 0, 5));
        // 指纹存放路径
        JTextField textField = new JTextField(FpManager.getPath(), 35);
        textField.setEditable(false);
        panel.add(textField);
        // 重新加载指纹
        JButton reload = new JButton(L.get("reload"));
        reload.addActionListener((e) -> {
            mFpTable.reloadData();
            refreshCount();
            UIHelper.showTipsDialog(L.get("reload_success"));
        });
        panel.add(reload);
        panel.add(new JLabel(L.get("count")));
        // 指纹数量展示
        mCountLabel = new JLabel(String.valueOf(FpManager.getCount()));
        panel.add(mCountLabel);
        panel.add(new JPanel(), "1w");
        // 指纹过滤功能
        mFpFilterRegexText = new HintTextField();
        mFpFilterRegexText.setHintText(L.get("regex_filter"));
        mFpFilterRegexText.addKeyListener(new KeyAdapter() {
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
        });
        panel.add(mFpFilterRegexText, "1w");
        JButton search = new JButton(L.get("search"));
        search.addActionListener((e) -> doSearch());
        panel.add(search);
        add(panel, "35px");
    }

    private void refreshCount() {
        String count = String.valueOf(FpManager.getCount());
        mCountLabel.setText(count);
    }

    private void addTablePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new HLayout(5));
        panel.setBorder(new EmptyBorder(0, 5, 5, 5));
        JPanel leftPanel = addLeftPanel();
        panel.add(leftPanel, "85px");
        mFpTable = new FpTable();
        JScrollPane scrollPane = new JScrollPane(mFpTable);
        scrollPane.setPreferredSize(new Dimension(scrollPane.getWidth(), 0));
        panel.add(scrollPane, "1w");
        add(panel, "1w");
    }

    private JPanel addLeftPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new VLayout(3));
        addButton(panel, L.get("add"), "add-item");
        addButton(panel, L.get("edit"), "edit-item");
        addButton(panel, L.get("delete"), "delete-item");
        addButton(panel, L.get("test"), "test");
        addButton(panel, L.get("clear_cache"), "do-clear-cache");
        return panel;
    }

    private void addButton(JPanel panel, String text, String actionCommand) {
        JButton btn = new JButton(text);
        btn.setActionCommand(actionCommand);
        btn.addActionListener(this);
        panel.add(btn);
    }

    private void doSearch() {
        String regex = mFpFilterRegexText.getText();
        if (StringUtils.isEmpty(regex)) {
            mFpTable.setRowFilter(null);
        } else {
            mFpTable.setRowFilter(RowFilter.regexFilter(regex));
        }
    }

    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        int rowIndex = mFpTable.getSelectedRow();
        FpData data = mFpTable.getFpData(rowIndex);
        switch (action) {
            case "add-item":
                FpData addData = (new FpDetailPanel()).showDialog();
                if (addData != null) {
                    mFpTable.addFpData(addData);
                    refreshCount();
                }
                break;
            case "edit-item":
                if (data == null) {
                    return;
                }
                FpData editData = new FpDetailPanel(data).showDialog();
                if (editData != null) {
                    mFpTable.setFpData(rowIndex, editData);
                }
                break;
            case "delete-item":
                if (data == null) {
                    return;
                }
                String info = "{" + data.toInfo() + "}";
                 int ret = UIHelper.showOkCancelDialog(L.get("fingerprint_delete_hint", info));
                if (ret == 0) {
                    mFpTable.removeFpData(rowIndex);
                    refreshCount();
                }
                break;
            case "test":
                showTestWindow();
                break;
            case "do-clear-cache":
                doClearCache();
                break;
        }
    }

    /**
     * 弹出指纹测试窗口
     */
    private void showTestWindow() {
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

    public String getTitleName() {
        return L.get("tab_name.fingerprint");
    }
}
