package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.common.L;

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
        prefixPanel.add(new JLabel(L.get("url_prefix_label")));
        mTextField = new HintTextField();
        mTextField.setHintText(L.get("url_prefix_input_hint"));
        prefixPanel.add(mTextField, "1w");
        // URL字典列表
        mWordlist = new SimpleWordlist();
        add(mWordlist, "1w");
        // 底部按钮布局
        JPanel bottomPanel = new JPanel(new HLayout(5, true));
        bottomPanel.setBorder(new EmptyBorder(10, 0, 5, 0));
        mKeepData = new JCheckBox(L.get("retain_data"));
        bottomPanel.add(mKeepData);
        bottomPanel.add(new JPanel(), "1w");
        JButton scanBtn = newButton(L.get("start_scan"), "scan-action");
        bottomPanel.add(scanBtn);
        JButton scanOnExitBtn = newButton(L.get("scan_on_exit"), "scan-on-exit-action");
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
        String action = e.getActionCommand();
        switch (action) {
            case "scan-action":
                doScan();
                break;
            case "scan-on-exit-action":
                boolean state = doScan();
                if (state) {
                    closeWindow();
                }
                break;
        }
    }

    /**
     * 开始扫描
     */
    private boolean doScan() {
        String prefix = mTextField.getText();
        List<String> data = mWordlist.getListData();
        // 如果存在前缀，对每一项进行拼接；如果不存在，直接使用列表的数据
        if (StringUtils.isNotEmpty(prefix)) {
            // 检测列表是否不为空
            if (!data.isEmpty()) {
                data.replaceAll(item -> {
                    // 检测是否需要添加 '/' 字符
                    if (!prefix.endsWith("/") && !item.startsWith("/")) {
                        item = "/" + item;
                    }
                    return prefix + item;
                });
            } else {
                // 列表为空，直接将前缀添加到列表
                data.add(prefix);
            }
        } else if (data == null || data.isEmpty()) {
            UIHelper.showTipsDialog(L.get("data_is_empty_hint"), this);
            return false;
        }
        // 调用监听器
        invokeOnImportUrlListener(data);
        return true;
    }

    /**
     * 调用 OnImportUrlListener 监听器
     *
     * @param data 导入的 URL 数据
     */
    private void invokeOnImportUrlListener(List<String> data) {
        if (mOnImportUrlListener != null) {
            this.mOnImportUrlListener.onImportUrl(data);
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
        mFrame = new JFrame(L.get("import_url_title"));
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
         * @param data   字典数据
         */
        void onImportUrl(List<String> data);
    }
}
