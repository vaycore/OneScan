package burp.vaycore.onescan.bean;

/**
 * 收集数据的实体类（用于列表展示）
 * <p>
 * Created by vaycore on 2023-12-23.
 */
public class CollectData<T> {

    /**
     * 列表中的 ID 显示
     */
    private int id;
    /**
     * 数据所属域名
     */
    private String domain;
    /**
     * 数据的实例
     */
    private T data;

    public CollectData() {
    }

    public CollectData(int id, String domain, T data) {
        this.id = id;
        this.domain = domain;
        this.data = data;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
