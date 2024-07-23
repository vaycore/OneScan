package burp.vaycore.common.config;

import burp.vaycore.common.utils.StringUtils;

import java.util.ArrayList;

/**
 * 配置管理器
 * <p>
 * Created by vaycore on 2022-01-28.
 */
public class ConfigManager {

    private final ConfigContext mConfigContext;

    public ConfigManager(String configPath) {
        this(new ConfigContextImpl(configPath));
    }

    public ConfigManager(ConfigContext ctx) {
        if (ctx == null) {
            throw new IllegalStateException("config context is null.");
        }
        mConfigContext = ctx;
    }

    /**
     * 保存配置项
     *
     * @param key   配置项的key
     * @param value 配置项的值
     */
    public void put(String key, Object value) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        mConfigContext.saveSetting(key, value);
    }

    /**
     * 保存配置项
     *
     * @param key   配置项的key
     * @param value 配置项的值
     */
    public void put(String key, String value) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        mConfigContext.saveSetting(key, value);
    }

    /**
     * 保存配置项
     *
     * @param key   配置项的key
     * @param value 配置项的值
     */
    public void put(String key, int value) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        mConfigContext.saveSetting(key, value);
    }

    /**
     * 保存配置项
     *
     * @param key   配置项的key
     * @param value 配置项的值
     */
    public void put(String key, boolean value) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        mConfigContext.saveSetting(key, value);
    }

    /**
     * 保存配置项
     *
     * @param key   配置项的key
     * @param value 配置项的值
     */
    public void put(String key, ArrayList<String> value) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        mConfigContext.saveSetting(key, value);
    }

    /**
     * 获取配置项
     *
     * @param key 配置项的key
     * @return 配置项的值
     */
    public <T> T get(String key) {
        return get(key, null);
    }


    /**
     * 获取配置项
     *
     * @param key      配置项的key
     * @param defValue 配置为null时返回的默认值
     * @return 配置项的值
     */
    public <T> T get(String key, T defValue) {
        if (StringUtils.isEmpty(key)) {
            return defValue;
        }
        Object value = mConfigContext.loadSetting(key);
        if (value == null) {
            value = defValue;
        }
        return (T) value;
    }

    /**
     * 获取配置项
     *
     * @param key 配置项的key
     * @return 配置项的值
     */
    public String getString(String key) {
        return getString(key, "");
    }

    /**
     * 获取配置项
     *
     * @param key      配置项的key
     * @param defValue 配置为null时返回的默认值
     * @return 配置项的值
     */
    public String getString(String key, String defValue) {
        return get(key, defValue);
    }

    /**
     * 获取配置项
     *
     * @param key 配置项的key
     * @return 配置项的值
     */
    public int getInt(String key) {
        return getInt(key, 0);
    }

    /**
     * 获取配置项
     *
     * @param key      配置项的key
     * @param defValue 配置为null时返回的默认值
     * @return 配置项的值
     */
    public int getInt(String key, int defValue) {
        return get(key, defValue);
    }

    /**
     * 获取配置项
     *
     * @param key 配置项的key
     * @return 配置项的值
     */
    public boolean getBoolean(String key) {
        return getBoolean(key, false);
    }

    /**
     * 获取配置项
     *
     * @param key      配置项的key
     * @param defValue 配置为null时返回的默认值
     * @return 配置项的值
     */
    public boolean getBoolean(String key, boolean defValue) {
        return get(key, defValue);
    }

    /**
     * 获取配置项
     *
     * @param key 配置项的key
     * @return 配置项的值
     */
    public ArrayList<String> getList(String key) {
        return getList(key, new ArrayList<>());
    }

    /**
     * 获取配置项
     *
     * @param key      配置项的key
     * @param defValue 配置为null时返回的默认值
     * @return 配置项的值
     */
    public ArrayList<String> getList(String key, ArrayList<String> defValue) {
        return get(key, defValue);
    }

    /**
     * 配置项是否存在
     *
     * @param key 配置项的key
     * @return 是否存在 key 所对应的配置项
     */
    public boolean hasKey(String key) {
        return mConfigContext.hasSetting(key);
    }

    /**
     * 删除配置项
     *
     * @param key 配置项的key
     */
    public void remove(String key) {
        mConfigContext.removeSetting(key);
    }
}
