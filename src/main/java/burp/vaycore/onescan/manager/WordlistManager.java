package burp.vaycore.onescan.manager;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.common.Config;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * 字典管理
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class WordlistManager {
    public static final String KEY_PAYLOAD = "payload";
    public static final String KEY_HEADERS = "headers";
    public static final String KEY_USER_AGENT = "user-agent";
    public static final String KEY_WHITE_HOST = "white-host";
    public static final String KEY_BLACK_HOST = "black-host";
    public static final String KEY_EXCLUDE_HEADERS = "exclude-headers";
    private static String sWordlistDir;

    private WordlistManager() {
        throw new IllegalAccessError("manager class not support create instance.");
    }

    public static void init(String path) {
        init(path, false);
    }

    public static void init(String path, boolean reInitFile) {
        if (StringUtils.isEmpty(path)) {
            throw new IllegalArgumentException("Wordlist path is empty.");
        }
        if (!FileUtils.exists(path)) {
            FileUtils.mkdirs(path);
        }
        if (!FileUtils.isDir(path)) {
            throw new IllegalArgumentException("Wordlist path not found.");
        }
        sWordlistDir = path;
        initDirs();
        initDefaultWordlist(WordlistManager.KEY_PAYLOAD, "payload.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_HEADERS, "header.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_USER_AGENT, "user_agent.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_WHITE_HOST, "whitelist.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_BLACK_HOST, "blacklist.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_EXCLUDE_HEADERS, "exclude_header.txt", reInitFile);
    }

    private static void initDirs() {
        Field[] fields = WordlistManager.class.getDeclaredFields();
        for (Field field : fields) {
            String name = field.getName();
            if (name.startsWith("KEY_")) {
                try {
                    String value = (String) field.get(null);
                    String path = sWordlistDir + File.separator + value;
                    if (!FileUtils.isDir(path)) {
                        boolean state = FileUtils.mkdirs(path);
                        if (state) {
                            Logger.debug("initDirs: %s ok!", path);
                        }
                    }
                } catch (IllegalAccessException e) {
                    // ignored
                }
            }
        }
    }

    private static void initDefaultWordlist(String key, String resName, boolean reInitFile) {
        if (!reInitFile && Config.hasKey(key)) {
            return;
        }
        List<String> itemList = getItemList(key);
        String defaultItem = "default";
        if (!itemList.isEmpty()) {
            defaultItem = itemList.contains("default") ? "default" : itemList.get(0);
        }
        Config.put(key, defaultItem);
        // 检测一下对应字典文件是否存在，以免造成覆盖配置的问题
        if (!wordlistFileExists(key)) {
            InputStream is = Config.class.getClassLoader().getResourceAsStream(resName);
            ArrayList<String> list = FileUtils.readStreamToList(is);
            putList(key, list);
        }
    }

    public static String getItem(String key) {
        String item = Config.get(key);
        if (StringUtils.isEmpty(item)) {
            item = "default";
        }
        return item;
    }

    public static void putItem(String key, String item) {
        Config.put(key, item);
    }

    public static List<String> getList(String key) {
        checkInit();
        String item = getItem(key);
        String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
        ArrayList<String> list = FileUtils.readFileToList(path);
        if (list == null) {
            list = new ArrayList<>();
        }
        return list;
    }

    public static void putList(String key, List<String> list) {
        checkInit();
        if (list == null) {
            return;
        }
        String item = getItem(key);
        String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
        String content = StringUtils.join(list, "\n");
        FileUtils.writeFile(path, content);
    }

    public static void createList(String key, String name) {
        checkInit();
        String path = sWordlistDir + File.separator + key + File.separator + name + ".txt";
        if (FileUtils.isFile(path)) {
            throw new IllegalArgumentException("wordlist already exists");
        }
        // 创建空文件
        boolean state = FileUtils.writeFile(path, "");
        if (!state) {
            throw new IllegalArgumentException("wordlist create failed.");
        }
    }

    public static void deleteList(String key, String name) {
        checkInit();
        String path = sWordlistDir + File.separator + key + File.separator + name + ".txt";
        if (!FileUtils.exists(path)) {
            throw new IllegalArgumentException("wordlist not exists");
        }
        // 删除文件
        boolean state = FileUtils.deleteFile(path);
        if (!state) {
            throw new IllegalArgumentException("wordlist delete failed.");
        }
    }

    public static List<String> getItemList(String key) {
        checkInit();
        String path = sWordlistDir + File.separator + key;
        File file = new File(path);
        File[] files = file.listFiles((pathname) -> pathname.getName().endsWith(".txt") && pathname.isFile());
        List<String> result = new ArrayList<>();
        if (files == null || files.length == 0) {
            return result;
        }
        for (File items : files) {
            String itemPath = items.getName().replace(".txt", "");
            result.add(itemPath);
        }
        return result;
    }

    public static boolean wordlistFileExists(String key) {
        String item = getItem(key);
        String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
        return FileUtils.isFile(path);
    }

    private static void checkInit() {
        if (StringUtils.isEmpty(sWordlistDir) || !FileUtils.isDir(sWordlistDir)) {
            throw new IllegalArgumentException("WordlistManager no init.");
        }
    }

    public static List<String> getPayload() {
        return getList(WordlistManager.KEY_PAYLOAD);
    }

    public static List<String> getHeader() {
        return getList(WordlistManager.KEY_HEADERS);
    }

    public static List<String> getUserAgent() {
        return getList(WordlistManager.KEY_USER_AGENT);
    }

    public static List<String> getWhiteHost() {
        return getList(WordlistManager.KEY_WHITE_HOST);
    }

    public static List<String> getBlackHost() {
        return getList(WordlistManager.KEY_BLACK_HOST);
    }

    public static List<String> getExcludeHeader() {
        return getList(WordlistManager.KEY_EXCLUDE_HEADERS);
    }
}
