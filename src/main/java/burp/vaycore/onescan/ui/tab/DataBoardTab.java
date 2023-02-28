package burp.vaycore.onescan.ui.tab;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.IPUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.FilterRule;
import burp.vaycore.onescan.bean.TaskData;
import burp.vaycore.onescan.common.TableFilter;
import burp.vaycore.onescan.ui.base.BaseTab;
import burp.vaycore.onescan.ui.widget.TableFilterPanel;
import burp.vaycore.onescan.ui.widget.TaskTable;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;

/**
 * 数据看板
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class DataBoardTab extends BaseTab {

    private TaskTable mTaskTable;
    private JCheckBox mListenProxyMessage;
    private JCheckBox mEnableExcludeHeader;
    private JCheckBox mDisableHeaderReplace;
    private JCheckBox mDisableDirScan;
    private ArrayList<FilterRule> mLastFilters;

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
            data.setMethod(i % 12 == 0 ? "POST" : "GET");
            data.setHost("https://www.baidu.com");
            data.setUrl("/?s=" + i);
            data.setTitle("百度一下，你就知道");
            data.setIp(IPUtils.randomIPv4());
            data.setStatus(200);
            data.setLength(Utils.randomInt(99999));
            data.setReqResp(new Object());
            getTaskTable().addTaskData(data);
        }
    }

    public void init(Component requestTextEditor, Component responseTextEditor) {
        if (requestTextEditor == null || responseTextEditor == null) {
            return;
        }
        setLayout(new VLayout(0));

        // 控制栏
        JPanel controlPanel = new JPanel();
        controlPanel.setBorder(new EmptyBorder(0, 0, 0, 5));
        controlPanel.setFocusable(false);
        controlPanel.setLayout(new HLayout(5, true));
        add(controlPanel);
        // 代理监听开关
        mListenProxyMessage = newJCheckBox(controlPanel, "Listen Proxy Message");
        // 启用请求头排除开关
        mEnableExcludeHeader = newJCheckBox(controlPanel, "Enable ExcludeHeader");
        // 禁用请求头替换功能
        mDisableHeaderReplace = newJCheckBox(controlPanel, "Disable HeaderReplace");
        // 禁用递归扫描功能
        mDisableDirScan = newJCheckBox(controlPanel, "Disable DirScan");
        // 过滤设置
        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> showSetupFilterDialog(mLastFilters));
        controlPanel.add(new JPanel(), "1w");
        controlPanel.add(filterBtn, "65px");
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

    private JCheckBox newJCheckBox(JPanel panel, String text) {
        JCheckBox checkBox = new JCheckBox(text, false);
        checkBox.setFocusable(false);
        checkBox.setMargin(new Insets(5, 5, 5, 5));
        panel.add(checkBox);
        return checkBox;
    }

    public TaskTable getTaskTable() {
        return mTaskTable;
    }

    public boolean hasListenProxyMessage() {
        return mListenProxyMessage != null && mListenProxyMessage.isSelected();
    }

    public boolean hasEnableExcludeHeader() {
        return mEnableExcludeHeader != null && mEnableExcludeHeader.isSelected();
    }

    public boolean hasDisableHeaderReplace() {
        return mDisableHeaderReplace != null && mDisableHeaderReplace.isSelected();
    }

    public boolean hasDisableDirScan() {
        return mDisableDirScan != null && mDisableDirScan.isSelected();
    }

    /**
     * 设置过滤对话框
     *
     * @param rules 过滤规则
     */
    private void showSetupFilterDialog(ArrayList<FilterRule> rules) {
        TableFilterPanel panel = new TableFilterPanel(TaskTable.TaskTableModel.COLUMN_NAMES, rules);
        int state = UIHelper.showCustomDialog("Setup filter", new String[]{"OK", "Cancel", "Reset"}, panel);
        if (state == JOptionPane.YES_OPTION) {
            ArrayList<FilterRule> filterRules = panel.exportRules();
            ArrayList<TableFilter> filters = new ArrayList<>();
            for (FilterRule rule : filterRules) {
                TableFilter filter = new TableFilter(rule);
                filters.add(filter);
            }
            mTaskTable.setRowFilter(RowFilter.andFilter(filters));
            mLastFilters = filterRules;
        } else if (state == 2) {
            mTaskTable.setRowFilter(null);
            mLastFilters = null;
        }
    }
}
