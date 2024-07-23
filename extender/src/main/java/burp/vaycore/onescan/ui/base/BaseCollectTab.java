package burp.vaycore.onescan.ui.base;

import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.common.CollectFilter;
import burp.vaycore.onescan.ui.widget.CollectTable;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

/**
 * 数据收集页面基类
 * <p>
 * Created by vaycore on 2023-12-21.
 */
public abstract class BaseCollectTab<T> extends BaseTab {

    private HintTextField mSearchInputUI;
    private CollectTable<T> mTableUI;
    private JCheckBox mReverseUI;
    private JCheckBox mIgnoreCaseUI;

    @Override
    protected void initData() {

    }

    @Override
    protected void initView() {
        setLayout(new VLayout(0));
        initSearchPanel();
        initOptionsPanel();
        initTablePanel();
    }

    private void initSearchPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        panel.setBorder(new EmptyBorder(5, 5, 0, 5));
        mSearchInputUI = new HintTextField(35);
        panel.add(mSearchInputUI, "35%");
        mSearchInputUI.setHintText("Regex filter.");
        mSearchInputUI.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyChar() == KeyEvent.VK_ENTER) {
                    doSearch();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {
                String text = mSearchInputUI.getText();
                if (StringUtils.isEmpty(text)) {
                    doSearch();
                }
            }
        });
        JButton search = new JButton("Search");
        search.addActionListener((e) -> doSearch());
        panel.add(search);
        add(panel);
    }

    private void initOptionsPanel() {
        JPanel panel = new JPanel(new HLayout(5, true));
        panel.setBorder(new EmptyBorder(0, 5, 0, 5));
        mReverseUI = new JCheckBox("Reverse");
        panel.add(mReverseUI);
        mIgnoreCaseUI = new JCheckBox("Ignore Case");
        panel.add(mIgnoreCaseUI);
        add(panel);
    }

    private void initTablePanel() {
        CollectTable.CollectTableModel<T> tableModel = buildTableModel();
        mTableUI = new CollectTable<>(tableModel);
        JScrollPane scrollPane = new JScrollPane(mTableUI);
        add(scrollPane, "1w");
    }

    /**
     * 构建 TableModel 实例
     */
    protected abstract CollectTable.CollectTableModel<T> buildTableModel();

    private void doSearch() {
        String regex = mSearchInputUI.getText();
        if (StringUtils.isEmpty(regex)) {
            mTableUI.setRowFilter(null);
        } else {
            mTableUI.setRowFilter(new CollectFilter<>(
                    regex,
                    mReverseUI.isSelected(),
                    mIgnoreCaseUI.isSelected()));
        }
    }

    /**
     * 设置路径（展示对应路径的数据）
     *
     * @param path 路径
     */
    public abstract void setupPath(String path);

    /**
     * 获取数据数量
     *
     * @return 数量
     */
    public abstract int getDataCount();
}
