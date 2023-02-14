package burp.vaycore.onescan.ui.tab;

import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.ui.base.BaseTab;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.onescan.ui.widget.TaskTable;

import javax.swing.*;
import java.awt.*;

/**
 * 数据看板
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class DataBoardTab extends BaseTab {

    private TaskTable mTaskTable;
    private JCheckBox mListenProxyMessage;

    @Override
    protected void initData() {
    }

    @Override
    protected void initView() {
    }

    public String getTitleName() {
        return "Databoard";
    }

    public void testInit() {
        init(new JTextArea("Request"), new JTextArea("Response"));
        // 添加测试数据
        for (int i = 0; i < 100; i++) {
            TaskData data = new TaskData();
            data.setMethod("GET");
            data.setHost("https://www.baidu.com");
            data.setUrl("/?s=" + i);
            data.setTitle("百度一下，你就知道");
            data.setIp("21.33.44.55");
            data.setStatus(200);
            data.setLength(32151);
            data.setReqResp(new Object());
            getTaskTable().addTaskData(data);
        }
    }

    public void init(Component requestTextEditor, Component responseTextEditor) {
        if (requestTextEditor == null || responseTextEditor == null) {
            return;
        }
        setLayout(new VLayout(0));
        // 代理监听开关
        mListenProxyMessage = new JCheckBox("Listen Proxy Message", false);
        mListenProxyMessage.setFocusable(false);
        mListenProxyMessage.setMargin(new Insets(5, 5, 5, 5));
        add(mListenProxyMessage);

        // 主面板
        JSplitPane mainSplitPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPanel.setResizeWeight(0.55D);
        mainSplitPanel.setDividerSize(3);
        // 请求列表
        mTaskTable = new TaskTable();
        JScrollPane scrollPane = new JScrollPane(mTaskTable);
        scrollPane.setPreferredSize(new Dimension(scrollPane.getWidth(), 0));

        // 请求和响应面板
        JSplitPane dataSplitPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        dataSplitPanel.setResizeWeight(0.5D);
        dataSplitPanel.setDividerSize(3);
        dataSplitPanel.add(requestTextEditor, JSplitPane.LEFT);
        dataSplitPanel.add(responseTextEditor, JSplitPane.RIGHT);

        // 添加子面板控件
        mainSplitPanel.add(scrollPane, JSplitPane.LEFT);
        mainSplitPanel.add(dataSplitPanel, JSplitPane.RIGHT);
        // 将布局进行展示
        add(mainSplitPanel, "100%");
    }

    public TaskTable getTaskTable() {
        return mTaskTable;
    }

    public boolean hasListenProxyMessage() {
        if (mListenProxyMessage == null) {
            return false;
        }
        return mListenProxyMessage.isSelected();
    }
}
