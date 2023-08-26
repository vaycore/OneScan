package burp.vaycore.onescan.common;

import burp.vaycore.common.config.ConfigManager;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.PathUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.manager.WordlistManager;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;
import burp.vaycore.onescan.ui.widget.payloadlist.SimplePayloadList;
import com.google.gson.internal.LinkedTreeMap;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;

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
    public static final String KEY_SCAN_LEVEL_DIRECT = "scan-level-direct";
    public static final String KEY_SCAN_LEVEL = "scan-level";
    public static final String KEY_WEB_NAME_COLLECT_PATH = "web-name-collect-path";
    public static final String KEY_JSON_FIELD_COLLECT_PATH = "json-field-collect-path";
    public static final String KEY_EXCLUDE_SUFFIX = "exclude-suffix";
    public static final String KEY_HAE_PLUGIN_PATH = "hae-plugin-path";
    public static final String KEY_INCLUDE_METHOD = "include-method";
    public static final String KEY_WORDLIST_PATH = "dict-path";
    // 首页开关配置项
    public static final String KEY_ENABLE_LISTEN_PROXY = "enable-listen-proxy";
    public static final String KEY_ENABLE_EXCLUDE_HEADER = "enable-exclude-header";
    public static final String KEY_ENABLE_REPLACE_HEADER = "enable-replace-header";
    public static final String KEY_ENABLE_DIR_SCAN = "enable-dir-scan";
    private static ConfigManager sConfigManager;
    private static String sConfigPath;
    // 配置常量值
    public static final String DIRECT_LEFT = "left";
    public static final String DIRECT_RIGHT = "right";

    public static void init() {
        sConfigPath = getWorkDir() + "config.json";
        sConfigManager = new ConfigManager(sConfigPath);
        initDefaultConfig(Config.KEY_VERSION, Constants.PLUGIN_VERSION);
        initDefaultConfig(Config.KEY_QPS_LIMIT, "1024");
        initDefaultConfig(Config.KEY_SCAN_LEVEL_DIRECT, "left");
        initDefaultConfig(Config.KEY_SCAN_LEVEL, "99");
        initDefaultConfig(Config.KEY_WEB_NAME_COLLECT_PATH, getWorkDir() + "web_name.txt");
        initDefaultConfig(Config.KEY_JSON_FIELD_COLLECT_PATH, getWorkDir() + "json-fields");
        initDefaultConfig(KEY_EXCLUDE_SUFFIX, "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|" +
                "bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|" +
                "mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|" +
                "ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|" +
                "woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip");
        initDefaultConfig(Config.KEY_INCLUDE_METHOD, "GET|POST");
        initDefaultConfig(Config.KEY_WORDLIST_PATH, getWorkDir() + "wordlist");
        // 默认开关配置
        initDefaultConfig(Config.KEY_ENABLE_LISTEN_PROXY, "false");
        initDefaultConfig(Config.KEY_ENABLE_EXCLUDE_HEADER, "false");
        initDefaultConfig(Config.KEY_ENABLE_REPLACE_HEADER, "true");
        initDefaultConfig(Config.KEY_ENABLE_DIR_SCAN, "true");
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
        String path = getWorkDir() + "fingerprint.json";
        if (!FileUtils.isFile(path)) {
            InputStream is = Config.class.getClassLoader().getResourceAsStream("fingerprint.json");
            String content = FileUtils.readStreamToString(is);
            FileUtils.writeFile(path, content);
        }
        FpManager.init(path);
    }

    private static void onVersionUpgrade() {
        String version = getVersion();
        if (!version.equals(Constants.PLUGIN_VERSION)) {
            putVersion(Constants.PLUGIN_VERSION);
            upgradeDomain();
            upgradeRemoveHeaderList();
            upgradeWordlist();
        }
    }

    private static void upgradeDomain() {
        String configJson = FileUtils.readFileToString(sConfigPath);
        if (configJson.contains("{{mdomain}}")) {
            configJson = configJson.replace("{{mdomain}}", "{{domain.name}}");
            boolean state = FileUtils.writeFile(sConfigPath, configJson);
            if (state) {
                Logger.info("Replace all {{mdomain}} to {{domain.name}} ok!");
                init();
            }
        }
    }

    private static void upgradeRemoveHeaderList() {
        // 将remove-header-list配置项迁移到新字段
        if (hasKey("remove-header-list")) {
            ArrayList<String> list = getList("remove-header-list");
            WordlistManager.putList(WordlistManager.KEY_EXCLUDE_HEADERS, list);
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
            WordlistManager.putList(WordlistManager.KEY_WHITE_HOST, list);
            sConfigManager.remove("whitelist");
        }

        if (hasKey("blacklist")) {
            list = getList("blacklist");
            WordlistManager.putList(WordlistManager.KEY_BLACK_HOST, list);
            sConfigManager.remove("blacklist");
        }

        if (hasKey("exclude-header")) {
            list = getList("exclude-header");
            WordlistManager.putList(WordlistManager.KEY_EXCLUDE_HEADERS, list);
            sConfigManager.remove("exclude-header");
        }
    }

    private static void onPreloadConfig() {
        preparePayloadProcessList();
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

    private static void preparePayloadProcessList() {
        ArrayList<LinkedTreeMap<String, Object>> mapItems = sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
        ArrayList<PayloadItem> result = new ArrayList<>();
        if (mapItems != null && !mapItems.isEmpty()) {
            // 转换 LinkedTreeMap 数据为 PayloadItem 对象
            for (LinkedTreeMap<String, Object> mapItem : mapItems) {
                PayloadItem item = new PayloadItem();
                Double id = (Double) mapItem.get("id");
                item.setId(id.intValue());
                item.setEnabled((Boolean) mapItem.get("enabled"));
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
        }
        put(Config.KEY_PAYLOAD_PROCESS_LIST, result);
    }

    public static ArrayList<PayloadItem> getPayloadProcessList() {
        checkInit();
        return sConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
    }
}