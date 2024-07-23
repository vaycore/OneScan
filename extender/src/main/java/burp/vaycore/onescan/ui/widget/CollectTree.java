package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.onescan.bean.CollectNode;
import burp.vaycore.onescan.manager.CollectManager;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.plaf.metal.MetalTreeUI;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * 数据收集的树组件
 * <p>
 * Created by vaycore on 2023-12-20.
 */
public class CollectTree extends JTree implements TreeSelectionListener, CollectManager.CollectNodeListener, ActionListener {

    private OnSelectPathListener mOnSelectPathListener;
    private final CollectTreeModel mTreeModel;

    public CollectTree() {
        super(new CollectTreeModel());
        mTreeModel = (CollectTreeModel) getModel();
        initView();
    }

    private void initView() {
        // 将 UI 设置为 MetalTreeUI 样式（主要是自带的 BurpTreeUI 有 BUG）
        setUI(new MetalTreeUI());
        // 设置根节点的树柄是否可见
        setShowsRootHandles(true);
        // 根节点是否显示
        setRootVisible(true);
        // 单选模式
        getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        // 设置为自定义的组件渲染
        setCellRenderer(new CustomTreeCellRenderer());
        // 添加选择事件监听
        addTreeSelectionListener(this);
        // 初始化菜单
        initTreeMenu();
        // 设置数据收集节点监听器
        CollectManager.setCollectNodeListener(this);
    }

    /**
     * 初始化菜单
     */
    private void initTreeMenu() {
        JPopupMenu popupMenu = new JPopupMenu();
        setComponentPopupMenu(popupMenu);
        addMenuItem(popupMenu, "折叠所有", "collapse-all");
        addMenuItem(popupMenu, "展开所有", "expand-all");
        addMenuItem(popupMenu, "删除选中节点", "delete-selected");
    }

    private void addMenuItem(JPopupMenu menu, String text, String action) {
        JMenuItem deleteItem = new JMenuItem(text);
        deleteItem.setActionCommand(action);
        deleteItem.addActionListener(this);
        menu.add(deleteItem);
    }

    @Override
    public void valueChanged(TreeSelectionEvent e) {
        if (mOnSelectPathListener == null) {
            return;
        }
        TreePath treePath = e.getPath();
        String path = getPath(treePath);
        mOnSelectPathListener.onSelectPath(path);
    }

    /**
     * 通过 TreePath 实例，获取路径
     *
     * @param treePath TreePath 实例
     * @return 失败返回null
     */
    private String getPath(TreePath treePath) {
        if (treePath == null) {
            return null;
        }
        Object[] pathObjects = treePath.getPath();
        StringBuilder result = new StringBuilder("/");
        for (int i = 1; i < pathObjects.length; i++) {
            if (i > 1) {
                result.append("/");
            }
            Object pathObj = pathObjects[i];
            result.append(pathObj);
        }
        return result.toString();
    }

    /**
     * 设置选择路径监听器
     *
     * @param l 监听器实例
     */
    public void setOnSelectItemListener(OnSelectPathListener l) {
        this.mOnSelectPathListener = l;
    }

    @Override
    public void onNodeInit() {
        mTreeModel.reloadTreeNode();
        // 将当前选择的路径设置为空
        if (this.mOnSelectPathListener != null) {
            this.mOnSelectPathListener.onSelectPath(null);
        }
    }

    @Override
    public void onNodeCreate(String nodePath, CollectNode node) {
        if (mTreeModel == null) {
            return;
        }
        mTreeModel.addTreeNode(node);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        switch (action) {
            case "collapse-all":
                doCollapseAll();
                break;
            case "expand-all":
                doExpandAll();
                break;
            case "delete-selected":
                doDeleteNode();
                break;
        }
    }

    /**
     * 折叠所有节点
     */
    private void doCollapseAll() {
        MutableTreeNode rootNode = (MutableTreeNode) mTreeModel.getRoot();
        for (int i = 0; i < rootNode.getChildCount(); i++) {
            TreeNode node = rootNode.getChildAt(i);
            TreePath path = new TreePath(new TreeNode[]{rootNode, node});
            collapsePath(path);
        }
    }

    /**
     * 展开所有节点
     */
    private void doExpandAll() {
        MutableTreeNode rootNode = (MutableTreeNode) mTreeModel.getRoot();
        for (int i = 0; i < rootNode.getChildCount(); i++) {
            TreeNode node = rootNode.getChildAt(i);
            TreePath path = new TreePath(new TreeNode[]{rootNode, node});
            expandPath(path);
        }
    }

    /**
     * 删除选中节点
     */
    private void doDeleteNode() {
        TreePath treePath = getSelectionPath();
        if (treePath == null) {
            UIHelper.showTipsDialog("请选择要删除的节点");
            return;
        }
        DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) treePath.getLastPathComponent();
        int opt = UIHelper.showOkCancelDialog("确认删除 '" + treeNode.toString() + "' 节点？");
        if (opt == JOptionPane.OK_OPTION) {
            String nodePath = getPath(treePath);
            CollectManager.delNodeByPath(nodePath);
            // 删除 UI 节点
            mTreeModel.removeTreeNode(treeNode);
        }
    }

    /**
     * 自定义组件渲染（主要定义图标的显示）
     */
    private static class CustomTreeCellRenderer extends DefaultTreeCellRenderer {

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            JLabel label = (JLabel) super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) value;
            Object userObject = treeNode.getUserObject();
            if (userObject == null) {
                return label;
            }
            if (!(userObject instanceof CollectNode)) {
                label.setText(userObject.toString());
                return label;
            }
            CollectNode node = (CollectNode) userObject;
            label.setText(node.getName());
            // 设置节点的图标
            if (expanded) {
                label.setIcon(UIManager.getIcon("Tree.openIcon"));
            } else {
                label.setIcon(UIManager.getIcon("Tree.closedIcon"));
            }
            // 如果没有子节点，显示为文件图标（根节点除外）
            if (node.isNodesEmpty() && !"All".equals(node.getName())) {
                label.setIcon(UIManager.getIcon("FileView.fileIcon"));
            }
            return label;
        }
    }

    /**
     * 选择路径的事件监听接口
     */
    public interface OnSelectPathListener {

        /**
         * 选择路径事件
         *
         * @param path 返回选择的路径
         */
        void onSelectPath(String path);
    }

    private static class CollectTreeModel extends DefaultTreeModel {

        public CollectTreeModel() {
            super(loadTreeNode());
        }

        private static TreeNode loadTreeNode() {
            CollectNode root = CollectManager.getNodeByPath("/");
            return loadTreeNodeByCollect(root);
        }

        private static DefaultMutableTreeNode loadTreeNodeByCollect(CollectNode node) {
            DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode(node);
            List<CollectNode> nodes = node.getNodes();
            if (node.isNodesEmpty()) {
                return rootNode;
            }
            for (CollectNode nodeItem : nodes) {
                DefaultMutableTreeNode childTreeNode = loadTreeNodeByCollect(nodeItem);
                rootNode.add(childTreeNode);
            }
            return rootNode;
        }

        /**
         * 添加节点
         *
         * @param node 节点实例
         */
        public void addTreeNode(CollectNode node) {
            CollectNode parent = node.getParent();
            // 因为不显示空的父节点，所以当没有父节点时，不往下执行添加过程
            if (parent == null) {
                return;
            }
            // 父节点不为空，添加对应的子节点
            MutableTreeNode parentNode = findParentNodeByPath("/" + parent);
            if (parentNode == null) {
                parentNode = new DefaultMutableTreeNode(parent);
                // 在 Root 下添加新创建的父节点
                MutableTreeNode rootNode = (MutableTreeNode) getRoot();
                insertNodeInto(parentNode, rootNode, rootNode.getChildCount());
            }
            String nodePath = "/" + parent + "/" + node;
            // 如果子节点存在（不添加）
            MutableTreeNode exists = findNodeByPath(parentNode, nodePath);
            if (exists != null) {
                return;
            }
            int insertIndex = parentNode.getChildCount();
            insertNodeInto(new DefaultMutableTreeNode(node), parentNode, insertIndex);
        }

        /**
         * 通过路径，找到父节点位置
         *
         * @param nodePath 节点路径
         * @return 未找到返回null
         */
        private MutableTreeNode findParentNodeByPath(String nodePath) {
            MutableTreeNode rootNode = (MutableTreeNode) getRoot();
            int count = rootNode.getChildCount();
            for (int i = 0; i < count; i++) {
                MutableTreeNode node = (MutableTreeNode) rootNode.getChildAt(i);
                String path = "/" + node;
                if (path.equals(nodePath)) {
                    return node;
                }
            }
            return null;
        }

        /**
         * 通过路径，在父节点中找到子节点位置
         *
         * @param parentNode 父节点
         * @param nodePath   节点路径
         * @return 未找到返回null
         */
        private MutableTreeNode findNodeByPath(MutableTreeNode parentNode, String nodePath) {
            int count = parentNode.getChildCount();
            for (int i = 0; i < count; i++) {
                MutableTreeNode node = (MutableTreeNode) parentNode.getChildAt(i);
                String path = "/" + parentNode + "/" + node;
                if (path.equals(nodePath)) {
                    return node;
                }
            }
            return null;
        }

        /**
         * 删除树节点
         */
        public void removeTreeNode(TreeNode node) {
            if (node == null) {
                return;
            }
            TreeNode parent = node.getParent();
            if (parent == null) {
                // 删除所有节点后，重新加载根节点
                reloadTreeNode();
            } else {
                removeNodeFromParent((MutableTreeNode) node);
                // 如果没有子节点了，直接删除父节点
                if (parent.getChildCount() == 0) {
                    removeTreeNode(parent);
                }
            }
        }

        /**
         * 重新加载树节点
         */
        public void reloadTreeNode() {
            TreeNode rootNode = loadTreeNode();
            setRoot(rootNode);
        }
    }
}
