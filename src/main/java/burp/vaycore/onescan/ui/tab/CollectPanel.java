package burp.vaycore.onescan.ui.tab;

import burp.vaycore.common.layout.VLayout;
import burp.vaycore.onescan.manager.CollectManager;
import burp.vaycore.onescan.ui.base.BaseCollectTab;
import burp.vaycore.onescan.ui.base.BaseTab;
import burp.vaycore.onescan.ui.tab.collect.CommonCollectTab;
import burp.vaycore.onescan.ui.widget.CollectTree;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * 数据收集面板
 * <p>
 * Created by vaycore on 2023-12-19.
 */
public class CollectPanel extends BaseTab implements CollectTree.OnSelectPathListener {

    private JTabbedPane mTabPanel;

    @Override
    protected void initData() {

    }

    @Override
    protected void initView() {
        setLayout(new VLayout(0));
        JSplitPane splitPane = new JSplitPane();
        splitPane.setResizeWeight(0.1D);
        add(splitPane, "1w");
        // 目录树
        JComponent left = initTreeUI();
        splitPane.setLeftComponent(left);
        // Tab 面板
        mTabPanel = initTabPanel();
        splitPane.setRightComponent(mTabPanel);
    }

    private JComponent initTreeUI() {
        // 加载数据
        CollectTree treeUI = new CollectTree();
        treeUI.setOnSelectItemListener(this);
        // 支持滚动
        JScrollPane scrollPane = new JScrollPane(treeUI);
        scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));
        return scrollPane;
    }

    /**
     * 初始化 Tab 面板
     */
    private JTabbedPane initTabPanel() {
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        // 遍历数据收集模块，动态添加对应标签
        CollectManager.forEachModule(module -> {
            CommonCollectTab tab = new CommonCollectTab(module.getName());
            String title = String.format("%s (%d)", tab.getTitleName(), 0);
            tabbedPane.addTab(title, tab);
        });
        return tabbedPane;
    }

    @Override
    public String getTitleName() {
        return "Collect";
    }

    @Override
    public void onSelectPath(String path) {
        int tabCount = mTabPanel.getTabCount();
        for (int i = 0; i < tabCount; i++) {
            BaseCollectTab<?> tab = (BaseCollectTab<?>) mTabPanel.getComponentAt(i);
            tab.setupPath(path);
            // 在 Tab 标题中展示数据量
            int count = tab.getDataCount();
            String title = String.format("%s (%d)", tab.getTitleName(), count);
            mTabPanel.setTitleAt(i, title);
        }
    }
}
