package burp.vaycore.onescan.common;

import burp.vaycore.common.config.ConfigManager;
import burp.vaycore.common.filter.FilterRule;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.*;
import burp.vaycore.onescan.manager.CollectManager;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.onescan.ui.widget.payloadlist.ProcessingItem;
import burp.vaycore.onescan.ui.widget.payloadlist.SimplePayloadList;
import com.google.gson.internal.LinkedTreeMap;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 配置类
 * <p>
 * Created by vaycore on 2022-08-19.
 */
public class Config {
    // 配置项
    public static final String KEY_VERSION = "version";
    public static final String KEY_PAYLOAD_PROCESS_LIST = "payload-process-list";
    public static final String KEY_QPS_LIMIT = "qps-limit";
    public static final String KEY_REQUEST_DELAY = "request-delay";
    public static final String KEY_SCAN_LEVEL_DIRECT = "scan-level-direct";
    public static final String KEY_SCAN_LEVEL = "scan-level";
    public static final String KEY_RETRY_COUNT = "retry-count";
    public static final String KEY_MAX_DISPLAY_LENGTH = "max-display-length";
    public static final String KEY_COLLECT_PATH = "collect-path";
    public static final String KEY_EXCLUDE_SUFFIX = "exclude-suffix";
    public static final String KEY_INCLUDE_METHOD = "include-method";
    public static final String KEY_WORDLIST_PATH = "dict-path";
    public static final String KEY_DATABOARD_FILTER_RULES = "databoard-filter-rules";
    // 首页开关配置项
    public static final String KEY_ENABLE_LISTEN_PROXY = "enable-listen-proxy";
    public static final String KEY_ENABLE_REMOVE_HEADER = "enable-remove-header";
    public static final String KEY_ENABLE_REPLACE_HEADER = "enable-replace-header";
    public static final String KEY_ENABLE_DIR_SCAN = "enable-dir-scan";
    public static final String KEY_ENABLE_PAYLOAD_PROCESSING = "payload-processing";
    // 配置常量值
    public static final String DIRECT_LEFT = "left";
    public static final String DIRECT_RIGHT = "right";

    private static String sWorkDir;
    private static String sConfigPath;
    private static ConfigManager sConfigManager;

    public static void init(String wordDir) {
        sWorkDir = wordDir;
        sConfigPath = getWorkDir() + "config.json";
        sConfigManager = new ConfigManager(sConfigPath);
        initDefaultConfig(Config.KEY_VERSION, Constants.PLUGIN_VERSION);
        initDefaultConfig(Config.KEY_QPS_LIMIT, "1024");
        initDefaultConfig(Config.KEY_REQUEST_DELAY, "0");
        initDefaultConfig(Config.KEY_SCAN_LEVEL_DIRECT, "left");
        initDefaultConfig(Config.KEY_SCAN_LEVEL, "99");
        initDefaultConfig(Config.KEY_RETRY_COUNT, "3");
        initDefaultConfig(Config.KEY_MAX_DISPLAY_LENGTH, "0");
        initDefaultConfig(Config.KEY_COLLECT_PATH, getWorkDir() + "collect");
        initDefaultConfig(KEY_EXCLUDE_SUFFIX, "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|" +
                "bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|" +
                "mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|" +
                "ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|" +
                "woff2|xbm|xls|xlsx|xpm|xul|xwd|zip");
        initDefaultConfig(Config.KEY_INCLUDE_METHOD, "GET|POST");
        initDefaultConfig(Config.KEY_WORDLIST_PATH, getWorkDir() + "wordlist");
        // 默认开关配置
        initDefaultConfig(Config.KEY_ENABLE_LISTEN_PROXY, "false");
        initDefaultConfig(Config.KEY_ENABLE_REMOVE_HEADER, "false");
        initDefaultConfig(Config.KEY_ENABLE_REPLACE_HEADER, "true");
        initDefaultConfig(Config.KEY_ENABLE_DIR_SCAN, "true");
        initDefaultConfig(Config.KEY_ENABLE_PAYLOAD_PROCESSING, "true");
        // 初始化数据收集管理
        CollectManager.init(get(Config.KEY_COLLECT_PATH));
        // 初始化字典管理
        WordlistManager.init(get(Config.KEY_WORDLIST_PATH));
        // 初始化指纹管理
        initFpManager();
        // 版本更新处理
        onVersionUpgrade();
        // 预加载一些需要实例化成对象的配置
        onPreloadConfig();
    }

    private static void initFpManager() {
        String path = getWorkDir() + "fp_config.json";
        if (!FileUtils.isFile(path)) {
            InputStream is = Config.class.getClassLoader().getResourceAsStream("fp_config.json");
            String content = FileUtils.readStreamToString(is);
            FileUtils.writeFile(path, content);
        }
        FpManager.init(path);
    }

    private static void onVersionUpgrade() {
        String version = getVersion();
        if (!version.equals(Constants.PLUGIN_VERSION)) {
            putVersion(Constants.PLUGIN_VERSION);
            backupConfig(version);
            upgradeConfigKey();
            upgradeDomain();
            upgradeHeaders();
            upgradeRemoveHeaderList();
            upgradeWordlist();
            upgradePayloadProcessing(version);
        }
    }

    /**
     * 备份配置（从0.x版本升级到1.x时备份）
     */
    private static void backupConfig(String oldVersion) {
        if (!oldVersion.startsWith("0.")) {
            return;
        }
        String bakPath = sConfigPath + ".bak";
        String content = FileUtils.readFileToString(sConfigPath);
        FileUtils.writeFile(bakPath, content);
        Logger.info("Welcome to update version %s, the configuration file has been backed up to the %s",
                Constants.PLUGIN_VERSION, bakPath);
    }

    private static void upgradeConfigKey() {
        // 将 enable-exclude-header 配置项迁移到新字段
        if (hasKey("enable-exclude-header")) {
            String enable = get("enable-exclude-header");
            sConfigManager.put(Config.KEY_ENABLE_REMOVE_HEADER, enable);
            sConfigManager.remove("enable-exclude-header");
        }
        // 将 white-host 配置项迁移到新字段
        if (hasKey("white-host")) {
            String enable = get("white-host");
            sConfigManager.put(WordlistManager.KEY_HOST_ALLOWLIST, enable);
            sConfigManager.remove("white-host");
        }
        // 将 black-host 配置项迁移到新字段
        if (hasKey("black-host")) {
            String enable = get("black-host");
            sConfigManager.put(WordlistManager.KEY_HOST_BLOCKLIST, enable);
            sConfigManager.remove("black-host");
        }
        // 将 exclude-headers 配置项迁移到新字段
        if (hasKey("exclude-headers")) {
            String enable = get("exclude-headers");
            sConfigManager.put(WordlistManager.KEY_REMOVE_HEADERS, enable);
            sConfigManager.remove("exclude-headers");
        }
        // 将 hae-plugin-path 配置项删除
        if (hasKey("hae-plugin-path")) {
            sConfigManager.remove("hae-plugin-path");
        }
    }

    private static void upgradeDomain() {
        String configJson = FileUtils.readFileToString(sConfigPath);
        if (configJson.contains("{{mdomain}}")) {
            configJson = configJson.replace("{{mdomain}}", "{{domain.name}}");
            boolean state = FileUtils.writeFile(sConfigPath, configJson);
            if (state) {
                Logger.info("Replace all {{mdomain}} to {{domain.name}} ok!");
                init(sWorkDir);
            }
        }
    }

    private static void upgradeHeaders() {
        List<String> defaultHeaders = WordlistManager.getList(WordlistManager.KEY_HEADERS, "default");
        // 默认配置已删除的情况
        if (defaultHeaders.isEmpty()) {
            return;
        }
        String joinResult = StringUtils.join(defaultHeaders, ",");
        // 新 headers 配置的 MD5 值
        String headersMd5 = Utils.md5(joinResult.getBytes(StandardCharsets.UTF_8));
        // 旧 headers 配置的 MD5 值
        String matchMd5 = "6eb466e03eda48b29275da941bfed84c";
        // 默认配置的 headers 如果无变更，将旧配置替换为新的配置
        if (headersMd5.equals(matchMd5)) {
            InputStream is = Config.class.getClassLoader().getResourceAsStream("header.txt");
            ArrayList<String> list = FileUtils.readStreamToList(is);
            WordlistManager.putList(WordlistManager.KEY_HEADERS, "default", list);
        }
    }

    private static void upgradeRemoveHeaderList() {
        // 将remove-header-list配置项迁移到新字段
        if (hasKey("remove-header-list")) {
            ArrayList<String> list = getList("remove-header-list");
            WordlistManager.putList(WordlistManager.KEY_REMOVE_HEADERS, list);
            sConfigManager.remove("remove-header-list");
        }
    }

    private static void upgradeWordlist() {
        ArrayList<String> list;
        if (hasKey("payload-list")) {
            list = getList("payload-list");
            WordlistManager.putList(WordlistManager.KEY_PAYLOAD, list);
            sConfigManager.remove("payload-list");
        }

        if (hasKey("header-list")) {
            list = getList("header-list");
            WordlistManager.putList(WordlistManager.KEY_HEADERS, list);
            sConfigManager.remove("header-list");
        }

        if (hasKey("user-agent-list")) {
            list = getList("user-agent-list");
            WordlistManager.putList(WordlistManager.KEY_USER_AGENT, list);
            sConfigManager.remove("user-agent-list");
        }

        if (hasKey("whitelist")) {
            list = getList("whitelist");
            WordlistManager.putList(WordlistManager.KEY_HOST_ALLOWLIST, list);
            sConfigManager.remove("whitelist");
        }

        if (hasKey("blacklist")) {
            list = getList("blacklist");
            WordlistManager.putList(WordlistManager.KEY_HOST_BLOCKLIST, list);
            sConfigManager.remove("blacklist");
        }

        if (hasKey("exclude-header")) {
            list = getList("exclude-header");
            WordlistManager.putList(WordlistManager.KEY_REMOVE_HEADERS, list);
            sConfigManager.remove("exclude-header");
        }

        if (hasKey("web-name-collect-path")) {
            sConfigManager.remove("web-name-collect-path");
        }

        if (hasKey("json-field-collect-path")) {
            sConfigManager.remove("json-field-collect-path");
        }
    }

    private static void upgradePayloadProcessing(String oldVersion) {
        // 版本检测（从 OneScan <= 1.3.7 版本升级时需要变更配置）
        String version = oldVersion.replace(".", "");
        int versionInt = StringUtils.parseInt(version);
        if (versionInt == 0 || versionInt > 137) {
            return;
        }
        // Merge Payload Processing 开关配置更新
        if (hasKey("merge-payload-processing")) {
            boolean configValue = getBoolean("merge-payload-processing");
            put(Config.KEY_ENABLE_PAYLOAD_PROCESSING, String.valueOf(configValue));
            sConfigManager.remove("merge-payload-processing");
        }
        // Payload Processing 配置结构更新
        if (hasKey(Config.KEY_PAYLOAD_PROCESS_LIST)) {
            ArrayList<LinkedTreeMap<String, Object>> items = sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
            ArrayList<ProcessingItem> newItems = new ArrayList<>();
            if (items != null && !items.isEmpty()) {
                ArrayList<PayloadItem> result = mapItemsConvert(items);
                ProcessingItem item = new ProcessingItem();
                item.setEnabled(true);
                item.setItems(result);
                item.setName("Low version rules");
                newItems.add(item);
            }
            sConfigManager.put(Config.KEY_PAYLOAD_PROCESS_LIST, newItems);
        }
    }

    private static void onPreloadConfig() {
        preparePayloadProcessList();
        prepareDataboardFilterRules();
    }

    private static void initDefaultConfig(String key, String defValue) {
        if (!hasKey(key)) {
            sConfigManager.put(key, defValue);
        }
    }

    private static void checkInit() {
        if (sConfigManager == null) {
            throw new IllegalStateException("Config class is not initialize");
        }
    }

    public static String getWorkDir() {
        if (StringUtils.isNotEmpty(sWorkDir) && FileUtils.isDir(sWorkDir)) {
            return sWorkDir;
        }
        return PathUtils.getUserHome() + ".config" + File.separator + "OneScan" + File.separator;
    }

    public static String getVersion() {
        return get(KEY_VERSION);
    }

    public static void putVersion(String version) {
        put(KEY_VERSION, version);
    }

    public static String getFilePath(String key) {
        return getFilePath(key, false);
    }

    public static String getFilePath(String key, boolean isDir) {
        checkInit();
        String path = sConfigManager.get(key);
        if (StringUtils.isEmpty(path)) {
            return path;
        }
        File dir = isDir ? new File(path) : new File(path).getParentFile();
        if (!dir.exists()) {
            boolean mkdirs = dir.mkdirs();
            Logger.debug("Config item path mkdirs: %s", mkdirs);
        }
        return path;
    }

    public static void put(String key, String text) {
        checkInit();
        sConfigManager.put(key, text);
    }

    public static void put(String key, Object obj) {
        checkInit();
        sConfigManager.put(key, obj);
    }

    public static String get(String key) {
        checkInit();
        return sConfigManager.get(key);
    }

    public static boolean getBoolean(String key) {
        checkInit();
        String value = sConfigManager.get(key);
        return "true".equals(value);
    }

    public static ArrayList<String> getList(String key) {
        checkInit();
        return sConfigManager.getList(key);
    }

    public static boolean hasKey(String key) {
        checkInit();
        return sConfigManager.hasKey(key);
    }

    public static void removeKey(String key) {
        checkInit();
        sConfigManager.remove(key);
    }

    private static void preparePayloadProcessList() {
        ArrayList<LinkedTreeMap<String, Object>> items;
        try {
            items = sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
            ArrayList<ProcessingItem> result = new ArrayList<>();
            if (items != null && !items.isEmpty()) {
                for (LinkedTreeMap<String, Object> mapItem : items) {
                    ProcessingItem item = new ProcessingItem();
                    item.setEnabled((Boolean) mapItem.get("enabled"));
                    String mergeValue = String.valueOf(mapItem.get("merge"));
                    item.setMerge(Boolean.parseBoolean(mergeValue));
                    String name = String.valueOf(mapItem.get("name"));
                    item.setName(name);
                    ArrayList<LinkedTreeMap<String, Object>> payloadMapItems =
                            (ArrayList<LinkedTreeMap<String, Object>>) mapItem.get("items");
                    ArrayList<PayloadItem> payloadItems = mapItemsConvert(payloadMapItems);
                    item.setItems(payloadItems);
                    result.add(item);
                }
            }
            put(Config.KEY_PAYLOAD_PROCESS_LIST, result);
        } catch (Exception e) {
            // 版本更新时，前面会有一次配置转换过程
            // 已经转换成 ArrayList<ProcessingItem> 类型的实例，类型会转换失败。忽略此错误即可
        }
    }

    private static ArrayList<PayloadItem> mapItemsConvert(ArrayList<LinkedTreeMap<String, Object>> items) {
        ArrayList<PayloadItem> result = new ArrayList<>();
        if (items == null || items.isEmpty()) {
            return result;
        }
        // 转换 LinkedTreeMap 数据为 PayloadItem 对象
        for (LinkedTreeMap<String, Object> mapItem : items) {
            PayloadItem item = new PayloadItem();
            Double scope = (Double) mapItem.get("scope");
            item.setScope(scope.intValue());
            PayloadRule rule = SimplePayloadList.getPayloadRuleByType((String) mapItem.get("ruleType"));
            if (rule == null) {
                continue;
            }
            LinkedTreeMap<String, Object> ruleMap = (LinkedTreeMap<String, Object>) mapItem.get("rule");
            ArrayList<String> ruleParamValues = (ArrayList<String>) ruleMap.get("paramValues");
            for (int j = 0; j < rule.paramCount(); j++) {
                String paramValue = ruleParamValues.get(j);
                rule.setParamValue(j, paramValue);
            }
            item.setRule(rule);
            result.add(item);
        }
        return result;
    }

    private static void prepareDataboardFilterRules() {
        Object obj = sConfigManager.get(Config.KEY_DATABOARD_FILTER_RULES);
        if (obj == null) {
            obj = new ArrayList<>();
        }
        String json = GsonUtils.toJson(obj);
        ArrayList<FilterRule> rules = GsonUtils.toList(json, FilterRule.class);
        put(Config.KEY_DATABOARD_FILTER_RULES, rules);
    }

    public static ArrayList<ProcessingItem> getPayloadProcessList() {
        checkInit();
        return sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
    }

    public static ArrayList<FilterRule> getDataboardFilterRules() {
        checkInit();
        return sConfigManager.get(Config.KEY_DATABOARD_FILTER_RULES);
    }
}