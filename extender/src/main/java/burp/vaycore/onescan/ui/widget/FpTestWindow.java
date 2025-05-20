package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * 指纹测试窗口
 * <p>
 * Created by vaycore on 2025-05-17.
 */
public class FpTestWindow extends JPanel implements ActionListener {

    private final String request;
    private final String response;
    private JTextArea mReqEditor;
    private JTextArea mRespEditor;
    private JButton mResetBtn;
    private JButton mTestBtn;
    private JButton mCloseBtn;
    private JFrame mFrame;
    private FpTestResultPanel mTestResultPanel;

    public FpTestWindow() {
        this(null, null);
    }

    public FpTestWindow(String request, String response) {
        this.request = request;
        this.response = response;
        initView();
        initEvent();
    }

    private void initView() {
        setLayout(new VLayout(3));
        setBorder(new EmptyBorder(5, 5, 5, 5));
        // 测试请求、响应输入框布局
        JPanel reqRespPanel = new JPanel(new HLayout(1));
        add(reqRespPanel, "3w");
        // 测试请求输入框
        mReqEditor = new JTextArea(request);
        JScrollPane reqScrollPane = new JScrollPane(mReqEditor);
        reqScrollPane.setBorder(new TitledBorder(L.get("request") + "："));
        reqRespPanel.add(reqScrollPane, "50%");
        // 测试响应输入框
        mRespEditor = new JTextArea(response);
        JScrollPane respScrollPane = new JScrollPane(mRespEditor);
        respScrollPane.setBorder(new TitledBorder(L.get("response") + "："));
        reqRespPanel.add(respScrollPane, "50%");
        // 测试按钮
        mTestBtn = new JButton(L.get("test"));
        mTestBtn.setActionCommand("test");
        add(mTestBtn);
        // 测试结果信息
        add(new JLabel(L.get("test_result")));
        mTestResultPanel = new FpTestResultPanel();
        add(mTestResultPanel, "2w");
        // 底部布局
        JPanel bottomPanel = new JPanel(new HLayout(5, true));
        bottomPanel.add(new JPanel(), "1w");
        add(bottomPanel);
        // 重置按钮
        mResetBtn = new JButton(L.get("reset"));
        mResetBtn.setActionCommand("reset");
        bottomPanel.add(mResetBtn);
        // 关闭按钮
        mCloseBtn = new JButton(L.get("close"));
        mCloseBtn.setActionCommand("close");
        bottomPanel.add(mCloseBtn);
    }

    private void initEvent() {
        mTestBtn.addActionListener(this);
        mCloseBtn.addActionListener(this);
        mResetBtn.addActionListener(this);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "test":
                doTest();
                break;
            case "reset":
                doReset();
                break;
            case "close":
                closeWindow();
                break;
            default:
                break;
        }
    }

    /**
     * 测试指纹
     */
    private void doTest() {
        String reqText = mReqEditor.getText();
        String respText = mRespEditor.getText();
        if (StringUtils.isEmpty(reqText) && StringUtils.isEmpty(respText)) {
            mTestResultPanel.showTips(L.get("input_is_empty"));
            return;
        }
        if (StringUtils.isNotEmpty(reqText)) {
            reqText = reqText.replace("\n", "\r\n");
        } else {
            reqText = "";
        }
        if (StringUtils.isNotEmpty(respText)) {
            respText = respText.replace("\n", "\r\n");
        } else {
            respText = "";
        }
        List<FpData> list = FpManager.check(reqText.getBytes(), respText.getBytes(), false);
        if (list.isEmpty()) {
            mTestResultPanel.showTips(L.get("no_test_result_hint"));
            return;
        }
        mTestResultPanel.setData(list);
    }

    /**
     * 重置测试数据
     */
    private void doReset() {
        mReqEditor.setText("");
        mRespEditor.setText("");
        mTestResultPanel.clearResult();
    }

    /**
     * 显示窗口
     */
    public void showWindow() {
        if (mFrame != null) {
            if (isShowing()) {
                mFrame.toFront();
            } else {
                mFrame.setVisible(true);
            }
            return;
        }
        mFrame = new JFrame(L.get("fingerprint_test_dialog_title"));
        // 窗口大小
        mFrame.setSize(750, 500);
        // 设置布局内容
        mFrame.setContentPane(this);
        // 其它设置
        mFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        mFrame.setLocationRelativeTo(null);
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
}
