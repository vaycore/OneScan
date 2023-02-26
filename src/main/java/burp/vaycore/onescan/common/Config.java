package burp.vaycore.onescan.common;

import burp.vaycore.common.config.ConfigManager;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.PathUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.ui.payloadlist.PayloadItem;
import burp.vaycore.onescan.ui.payloadlist.PayloadRule;
import burp.vaycore.onescan.ui.payloadlist.SimplePayloadList;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * 配置类
 * <p>
 * Created by vaycore on 2022-08-19.
 */
public class Config {

    public static final String KEY_VERSION = "version";
    public static final String KEY_PAYLOAD_LIST = "payload-list";
    public static final String KEY_PAYLOAD_PROCESS_LIST = "payload-process-list";
    public static final String KEY_HEADER_LIST = "header-list";
    public static final String KEY_UA_LIST = "user-agent-list";
    public static final String KEY_WHITE_LIST = "whitelist";
    public static final String KEY_BLACK_LIST = "blacklist";
    public static final String KEY_QPS_LIMIT = "qps-limit";
    public static final String KEY_WEB_NAME_COLLECT_PATH = "web-name-collect-path";
    public static final String KEY_JSON_FIELD_COLLECT_PATH = "json-field-collect-path";
    public static final String KEY_EXCLUDE_SUFFIX = "exclude-suffix";
    public static final String KEY_HAE_PLUGIN_PATH = "hae-plugin-path";
    public static final String KEY_INCLUDE_METHOD = "include-method";
    public static final String KEY_EXCLUDE_HEADER = "exclude-header";

    private static ConfigManager mConfigManager;
    private static String mConfigPath;

    public static void init() {
        // 初始化配置模块
        mConfigPath = getWorkDir() + "config.json";
        mConfigManager = new ConfigManager(mConfigPath);
        // 初始值配置
        initDefaultConfig(KEY_VERSION, Constants.PLUGIN_VERSION);
        initDefaultResourceConfig(KEY_PAYLOAD_LIST, "payload.txt");
        initDefaultResourceConfig(KEY_HEADER_LIST, "header.txt");
        initDefaultResourceConfig(KEY_UA_LIST, "user_agent.txt");
        initDefaultResourceConfig(KEY_WHITE_LIST, "whitelist.txt");
        initDefaultResourceConfig(KEY_BLACK_LIST, "blacklist.txt");
        initDefaultConfig(KEY_QPS_LIMIT, "1024");
        initDefaultConfig(KEY_WEB_NAME_COLLECT_PATH, getWorkDir() + "web_name.txt");
        initDefaultConfig(KEY_JSON_FIELD_COLLECT_PATH, getWorkDir() + "json-fields");
        initDefaultConfig(KEY_EXCLUDE_SUFFIX, "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|" +
                "bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|" +
                "mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|" +
                "ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|" +
                "woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip");
        initDefaultConfig(KEY_INCLUDE_METHOD, "GET|POST");
        initDefaultResourceConfig(KEY_EXCLUDE_HEADER, "exclude_header.txt");
        // 版本更新处理
        onVersionUpgrade();
        // 预加载一些需要实例化成对象的配置
        onPreloadConfig();
    }

    private static void onVersionUpgrade() {
        // 版本更新，配置也需要更新，更新后保留旧配置
        String version = Config.getVersion();
        if (!version.equals(Constants.PLUGIN_VERSION)) {
            // 在配置文件中更新版本号
            putVersion(Constants.PLUGIN_VERSION);
            // 如果包含{{mdomain}}，将整个配置文件的{{mdomain}}替换为{{domain.name}}
            String configJson = FileUtils.readFileToString(mConfigPath);
            if (configJson.contains("{{mdomain}}")) {
                configJson = configJson.replace("{{mdomain}}", "{{domain.name}}");
                boolean state = FileUtils.writeFile(mConfigPath, configJson);
                if (state) {
                    Logger.info("Replace all {{mdomain}} to {{domain.name}} ok!");
                    init();
                }
            }
            // 将remove-header-list配置项迁移到新字段
            if (mConfigManager.hasKey("remove-header-list")) {
                ArrayList<String> list = getList("remove-header-list");
                putList(KEY_EXCLUDE_HEADER, list);
                mConfigManager.remove("remove-header-list");
            }
        }
    }

    private static void onPreloadConfig() {
        // 处理 Payload Process 列表配置
        preparePayloadProcessList();
    }

    public static String getConfigPath() {
        return mConfigPath;
    }

    private static void initDefaultResourceConfig(String key, String resName) {
        if (mConfigManager.hasKey(key)) {
            return;
        }
        InputStream is = Config.class.getClassLoader().getResourceAsStream(resName);
        ArrayList<String> list = FileUtils.readStreamToList(is);
        mConfigManager.put(key, list);
    }

    private static void initDefaultConfig(String key, String defValue) {
        if (mConfigManager.hasKey(key)) {
            return;
        }
        mConfigManager.put(key, defValue);
    }

    private static void checkInit() {
        if (mConfigManager == null) {
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

    public static ArrayList<String> getPayloadList() {
        return Config.getList(Config.KEY_PAYLOAD_LIST);
    }

    public static ArrayList<String> getWhitelist() {
        return Config.getList(Config.KEY_WHITE_LIST);
    }

    public static ArrayList<String> getBlacklist() {
        return Config.getList(Config.KEY_BLACK_LIST);
    }

    public static ArrayList<String> getHeaderList() {
        return Config.getList(Config.KEY_HEADER_LIST);
    }

    public static String getFilePath(String key) {
        return getFilePath(key, false);
    }

    public static String getFilePath(String key, boolean isDir) {
        checkInit();
        String path = mConfigManager.get(key);
        if (StringUtils.isEmpty(path)) {
            return path;
        }
        File dir;
        if (isDir) {
            dir = new File(path);
        } else {
            dir = new File(path).getParentFile();
        }
        if (!dir.exists()) {
            boolean mkdirs = dir.mkdirs();
            Logger.debug("Config item path mkdirs: %s", mkdirs);
        }
        return path;
    }

    public static void put(String key, String text) {
        checkInit();
        mConfigManager.put(key, text);
    }

    public static void put(String key, Object obj) {
        checkInit();
        mConfigManager.put(key, obj);
    }

    public static void putList(String key, ArrayList<String> list) {
        checkInit();
        if (list == null) {
            return;
        }
        // 添加到缓存
        ArrayList<String> newList = new ArrayList<>(list);
        mConfigManager.put(key, newList);
    }

    public static String get(String key) {
        checkInit();
        return mConfigManager.get(key);
    }

    public static ArrayList<String> getList(String key) {
        checkInit();
        return mConfigManager.getList(key);
    }

    private static void preparePayloadProcessList() {
        ArrayList<HashMap<String, Object>> mapItems = mConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
        ArrayList<PayloadItem> result = new ArrayList<>();
        if (mapItems != null && !mapItems.isEmpty()) {
            // 转换HashMap数据为PayloadItem对象
            for (HashMap<String, Object> mapItem : mapItems) {
                PayloadItem item = new PayloadItem();
                item.setId((Integer) mapItem.get("id"));
                item.setEnabled((Boolean) mapItem.get("enabled"));
                item.setScope((Integer) mapItem.get("scope"));
                PayloadRule rule = SimplePayloadList.getPayloadRuleByType((String) mapItem.get("ruleType"));
                if (rule == null) {
                    continue;
                }
                HashMap<String, Object> ruleMap = (HashMap<String, Object>) mapItem.get("rule");
                ArrayList<String> ruleParamValues = (ArrayList<String>) ruleMap.get("paramValues");
                for (int j = 0; j < rule.paramCount(); j++) {
                    String paramValue = ruleParamValues.get(j);
                    rule.setParamValue(j, paramValue);
                }
                item.setRule(rule);
                result.add(item);
            }
        }
        // 将列表缓存
        put(Config.KEY_PAYLOAD_PROCESS_LIST, result);
    }

    public static ArrayList<PayloadItem> getPayloadProcessList() {
        checkInit();
        return mConfigManager.get(Config.KEY_PAYLOAD_PROCESS_LIST);
    }
}
