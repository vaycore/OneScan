package burp.vaycore.common.config;

import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.common.utils.PathUtils;
import burp.vaycore.common.utils.StringUtils;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * 配置上下文默认实现类
 * <p>
 * Created by vaycore on 2022-09-01.
 */
public class ConfigContextImpl implements ConfigContext {

    private final Map<String, Object> mConfigCache;
    private final String mConfigPath;

    public ConfigContextImpl(String configPath) {
        if (StringUtils.isEmpty(configPath)) {
            throw new IllegalArgumentException("config path is null!");
        }
        mConfigCache = new HashMap<>();
        mConfigPath = configPath;
        checkConfigPath();
        loadConfigByFile();
    }

    private void checkConfigPath() {
        File dir = PathUtils.getParentFile(mConfigPath);
        if (dir.exists()) {
            return;
        }
        boolean mkdirs = FileUtils.mkdirs(dir);
        if (mkdirs) {
            return;
        }
        throw new IllegalArgumentException("config path check error!");
    }

    private void loadConfigByFile() {
        // 可能是空文件
        if (!FileUtils.exists(mConfigPath)) {
            return;
        }
        String configData = FileUtils.readFileToString(mConfigPath);
        Map<String, Object> configMap = GsonUtils.toMap(configData);
        if (configMap == null || configMap.isEmpty()) {
            return;
        }
        mConfigCache.putAll(configMap);
    }

    @Override
    public void saveSetting(String key, Object value) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        mConfigCache.put(key, value);
        doWriteFile();
    }

    @Override
    public Object loadSetting(String key) {
        return mConfigCache.get(key);
    }

    @Override
    public void removeSetting(String key) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        if (hasSetting(key)) {
            mConfigCache.remove(key);
            doWriteFile();
        }
    }

    @Override
    public boolean hasSetting(String key) {
        return mConfigCache.containsKey(key);
    }

    /**
     * 执行写入文件操作
     */
    private void doWriteFile() {
        String configData = GsonUtils.toJson(mConfigCache);
        FileUtils.writeFile(mConfigPath, configData);
    }
}
