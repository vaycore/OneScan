package burp.vaycore.common.config;

/**
 * 配置上下文
 * <p>
 * Created by vaycore on 2022-01-28.
 */
public interface ConfigContext {
    /**
     * 保存配置项
     *
     * @param key   配置项的key
     * @param value 配置项的值
     */
    void saveSetting(String key, Object value);

    /**
     * 根据key加载配置项的值
     *
     * @param key 配置项的key
     * @return 返回配置项的值，读取失败返回 null
     */
    Object loadSetting(String key);

    /**
     * 删除配置项
     *
     * @param key 配置项的key
     */
    void removeSetting(String key);

    /**
     * 配置项是否存在
     *
     * @param key 配置项的key
     * @return 是否存在 key 所对应的配置项
     */
    boolean hasSetting(String key);
}