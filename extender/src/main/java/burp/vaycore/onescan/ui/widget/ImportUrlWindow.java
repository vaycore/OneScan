package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.widget.HintTextField;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * 导入 Url 窗口
 * <p>
 * Created by vaycore on 2024-11-24.
 */
public class ImportUrlWindow extends JPanel implements ActionListener {

    private HintTextField mTextField;
    private SimpleWordlist mWordlist;
    private JCheckBox mKeepData;
    private JFrame mFrame;
    private OnImportUrlListener mOnImportUrlListener;

    public ImportUrlWindow() {
        initView();
    }

    private void initView() {
        setLayout(new VLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));
        // URL前缀
        JPanel prefixPanel = new JPanel(new HLayout(0, true));
        add(prefixPanel);
        prefixPanel.add(new JLabel("URL前缀（非必选）："));
        mTextField = new HintTextField();
        mTextField.setHintText("URL前缀与列表的每一项进行拼接");
        prefixPanel.add(mTextField, "1w");
        // URL字典列表
        mWordlist = new SimpleWordlist();
        add(mWordlist, "1w");
        // 底部按钮布局
        JPanel bottomPanel = new JPanel(new HLayout(5, true));
        bottomPanel.setBorder(new EmptyBorder(10, 0, 5, 0));
        mKeepData = new JCheckBox("保留数据");
        bottomPanel.add(mKeepData);
        bottomPanel.add(new JPanel(), "1w");
        JButton scanBtn = newButton("开始扫描", "scan-action");
        bottomPanel.add(scanBtn);
        JButton scanOnExitBtn = newButton("扫描并关闭窗口", "scan-on-exit-action");
        bottomPanel.add(scanOnExitBtn);
        add(bottomPanel);
    }

    private JButton newButton(String text, String action) {
        JButton button = new JButton(text);
        button.setActionCommand(action);
        button.addActionListener(this);
        return button;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (mWordlist.isEmptyListData()) {
            UIHelper.showTipsDialog("data is empty", this);
            return;
        }
        String action = e.getActionCommand();
        switch (action) {
            case "scan-action":
                doScan();
                break;
            case "scan-on-exit-action":
                doScan();
                closeWindow();
                break;
        }
    }

    private void doScan() {
        List<String> data = mWordlist.getListData();
        String prefix = mTextField.getText();
        // 调用事件
        if (mOnImportUrlListener != null) {
            this.mOnImportUrlListener.onImportUrl(prefix, data);
        }
    }

    /**
     * 是否保留数据
     *
     * @return true=保留；false=不保留
     */
    private boolean isKeepData() {
        if (mKeepData == null) {
            return false;
        }
        return mKeepData.isSelected();
    }

    /**
     * 显示窗口
     */
    public void showWindow() {
        if (isShowing()) {
            mFrame.toFront();
            return;
        }
        if (!isKeepData()) {
            mTextField.setText("");
            mWordlist.setListData(new ArrayList<>());
        }
        mFrame = new JFrame("Import Url");
        // 窗口大小
        mFrame.setSize(460, 480);
        // 设置布局内容
        mFrame.setContentPane(this);
        // 其它设置
        mFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        mFrame.setLocationRelativeTo(null);
        mFrame.setResizable(false);
        mFrame.setVisible(true);
    }

    /**
     * 关闭窗口
     */
    public void closeWindow() {
        if (mFrame != null && isShowing()) {
            mFrame.dispose();
        }
    }

    /**
     * 设置监听器
     *
     * @param l 监听器实例
     */
    public void setOnImportUrlListener(OnImportUrlListener l) {
        this.mOnImportUrlListener = l;
    }

    /**
     * 导入 Url 监听器
     */
    public interface OnImportUrlListener {

        /**
         * 导入 Url 事件
         *
         * @param prefix Url 前缀
         * @param data   字典数据
         */
        void onImportUrl(String prefix, List<String> data);
    }
}
