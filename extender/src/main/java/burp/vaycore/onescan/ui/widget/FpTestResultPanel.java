package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.VFlowLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class FpTestResultPanel extends JScrollPane {

    private JPanel mPanel;

    public FpTestResultPanel() {
        this(null);
    }

    public FpTestResultPanel(List<FpData> list) {
        super(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        getVerticalScrollBar().setUnitIncrement(20);
        initView();
        setData(list);
    }

    private void initView() {
        mPanel = new JPanel(new VFlowLayout(VFlowLayout.LEFT, false, false));
        setViewportView(mPanel);
    }

    /**
     * 设置数据列表
     *
     * @param list 数据列表
     */
    public void setData(List<FpData> list) {
        clearResult();
        if (list == null || list.isEmpty()) {
            return;
        }
        List<ItemData> applicationItems = new ArrayList<>();
        List<ItemData> webserverItems = new ArrayList<>();
        List<ItemData> osItems = new ArrayList<>();
        List<ItemData> langItems = new ArrayList<>();
        List<ItemData> frameworkItems = new ArrayList<>();
        List<ItemData> descriptionItems = new ArrayList<>();
        List<ItemData> colorItems = new ArrayList<>();
        List<Integer> colorLevels = new ArrayList<>();
        for (FpData item : list) {
            appendData(applicationItems, item.getApplication(), item.getColor());
            appendData(webserverItems, item.getWebserver(), item.getColor());
            appendData(osItems, item.getOS(), item.getColor());
            appendData(langItems, item.getLang(), item.getColor());
            appendData(frameworkItems, item.getFramework(), item.getColor());
            appendData(descriptionItems, item.getDescription(), item.getColor());
            // 颜色等级收集
            int colorLevel = FpManager.findColorLevelByName(item.getColor());
            colorLevels.add(colorLevel);
        }
        // 颜色计算
        String colorName = FpManager.upgradeColors(colorLevels);
        colorItems.add(new ItemData(colorName, colorName));
        // 将数据添加到布局中展示
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.application"), applicationItems));
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.webserver"), webserverItems));
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.os"), osItems));
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.lang"), langItems));
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.framework"), frameworkItems));
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.description"), descriptionItems));
        addToPanel(createItemsPanel(L.get("fingerprint_table_columns.color"), colorItems));
        UIHelper.refreshUI(this);
    }

    /**
     * 创建指纹 Items 布局
     *
     * @param title 对应标题
     * @param items 数据
     * @return 失败返回null
     */
    private JPanel createItemsPanel(String title, List<ItemData> items) {
        if (items == null || items.isEmpty()) {
            return null;
        }
        JPanel panel = new JPanel(new ToolTipPanelLayout());
        panel.setBorder(new TitledBorder(title + "："));
        for (ItemData item : items) {
            JLabel label = new JLabel(item.getTagName());
            label.setOpaque(true);
            Color bgColor = FpManager.findColorByName(item.getColorName());
            if (bgColor == null) {
                label.setBackground(Color.WHITE);
            } else {
                label.setBackground(bgColor);
            }
            EmptyBorder emptyBorder = new EmptyBorder(5, 15, 5, 15);
            LineBorder lineBorder = new LineBorder(Color.LIGHT_GRAY);
            label.setBorder(BorderFactory.createCompoundBorder(lineBorder, emptyBorder));
            panel.add(label);
        }
        return panel;
    }

    /**
     * 添加组件到主布局中
     *
     * @param c 组件实例
     */
    private void addToPanel(JComponent c) {
        if (c == null) {
            return;
        }
        mPanel.add(c);
    }

    /**
     * 向列表追加数据
     *
     * @param list      数据列表
     * @param data      数据
     * @param colorName 颜色名
     */
    private void appendData(List<ItemData> list, String data, String colorName) {
        if (StringUtils.isEmpty(data)) {
            return;
        }
        for (int i = 0; i < list.size(); i++) {
            ItemData item = list.get(i);
            // 如果添加重名的指纹数据，升级颜色
            if (item.getTagName().equals(data)) {
                int leftColorLevel = FpManager.findColorLevelByName(item.getColorName());
                int rightColorLevel = FpManager.findColorLevelByName(colorName);
                List<Integer> levels = new ArrayList<>();
                levels.add(leftColorLevel);
                levels.add(rightColorLevel);
                String newColorName = FpManager.upgradeColors(levels);
                item.setColorName(newColorName);
                list.set(i, item);
                return;
            }
        }
        list.add(new ItemData(data, colorName));
    }

    /**
     * 显示提示信息
     *
     * @param tips 提示信息字符串
     */
    public void showTips(String tips) {
        clearResult();
        if (mPanel != null) {
            mPanel.add(new JLabel(tips));
            UIHelper.refreshUI(this);
        }
    }

    /**
     * 清空指纹识别结果
     */
    public void clearResult() {
        if (mPanel != null && mPanel.getComponentCount() > 0) {
            mPanel.removeAll();
            UIHelper.refreshUI(this);
        }
    }

    /**
     * 标签 Item 数据
     */
    private static class ItemData {

        private String tagName;
        private String colorName;

        public ItemData(String tagName, String colorName) {
            this.tagName = tagName;
            this.colorName = colorName;
        }

        public String getTagName() {
            return tagName;
        }

        public void setTagName(String tagName) {
            this.tagName = tagName;
        }

        public String getColorName() {
            return colorName;
        }

        public void setColorName(String colorName) {
            this.colorName = colorName;
        }
    }

    /**
     * 标签流式布局管理器
     */
    private static class ToolTipPanelLayout extends FlowLayout {

        public ToolTipPanelLayout() {
            super(FlowLayout.LEFT, 3, 3);
        }

        @Override
        public Dimension preferredLayoutSize(Container parent) {
            synchronized (parent.getTreeLock()) {
                int width = parent.getWidth();
                if (width <= 0) {
                    Insets insets = parent.getInsets();
                    width = parent.getParent().getWidth() - insets.left - insets.right - getHgap() * 2;
                }
                int height = calculateHeight(parent, width);
                return new Dimension(width, height);
            }
        }

        private int calculateHeight(Container parent, int maxWidth) {
            Insets insets = parent.getInsets();
            int componentCount = parent.getComponentCount();
            int x = 0;
            int y = insets.top + getVgap();
            int rowHeight = 0;
            maxWidth -= insets.left + insets.right;
            for (int i = 0; i < componentCount; i++) {
                Component c = parent.getComponent(i);
                if (c.isVisible()) {
                    Dimension size = c.getPreferredSize();
                    if (x + size.width >= maxWidth) {
                        y += rowHeight + getVgap();
                        x = 0;
                        rowHeight = 0;
                    }
                    x += size.width + getHgap();
                    rowHeight = Math.max(rowHeight, size.height);
                }
            }
            y += rowHeight;
            return y + insets.bottom + getVgap();
        }
    }
}
