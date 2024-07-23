package burp.vaycore.onescan.bean;

import java.util.*;

/**
 * 数据收集的节点
 * <p>
 * Created by vaycore on 2023-12-26.
 */
public class CollectNode {

    /**
     * 节点名
     */
    private final String name;

    /**
     * 父节点
     */
    private CollectNode parent;

    /**
     * 子节点
     */
    private final List<CollectNode> node;

    /**
     * 当前节点的数据
     */
    private final Map<String, Set<String>> data;

    public CollectNode(String name) {
        node = new ArrayList<>();
        data = new HashMap<>();
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public CollectNode getParent() {
        return parent;
    }

    public void setParent(CollectNode parent) {
        this.parent = parent;
    }

    public void add(CollectNode node) {
        if (this.node.contains(node)) {
            return;
        }
        node.setParent(this);
        this.node.add(node);
    }

    public List<CollectNode> getNodes() {
        return node;
    }

    public boolean isNodesEmpty() {
        return this.node.isEmpty();
    }

    public List<String> putData(String name, List<String> list) {
        List<String> diff = new ArrayList<>();
        if (list == null || list.isEmpty()) {
            return diff;
        }
        Set<String> data = getData(name);
        for (String item : list) {
            if (!data.add(item)) {
                continue;
            }
            diff.add(item);
        }
        this.data.put(name, data);
        return diff;
    }

    public Set<String> getData(String name) {
        if (this.data.containsKey(name)) {
            return this.data.get(name);
        }
        return new LinkedHashSet<>();
    }

    public void clearNode() {
        this.node.clear();
        this.data.clear();
    }

    public void removeNode(CollectNode node) {
        if (!this.node.contains(node)) {
            return;
        }
        this.node.remove(node);
    }

    @Override
    public String toString() {
        return this.name;
    }
}
