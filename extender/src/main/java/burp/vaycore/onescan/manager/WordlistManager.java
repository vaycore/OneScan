package burp.vaycore.onescan.manager;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
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
    public static final String KEY_HOST_ALLOWLIST = "host-allowlist";
    public static final String KEY_HOST_BLOCKLIST = "host-blocklist";
    public static final String KEY_REMOVE_HEADERS = "remove-headers";
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
        onVersionUpgrade();
        initDirs();
        onCheckInvalidConfig();
        initDefaultWordlist(WordlistManager.KEY_PAYLOAD, "payload.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_HEADERS, "header.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_USER_AGENT, "user_agent.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_HOST_ALLOWLIST, "host_allowlist.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_HOST_BLOCKLIST, "host_blocklist.txt", reInitFile);
        initDefaultWordlist(WordlistManager.KEY_REMOVE_HEADERS, "remove_header.txt", reInitFile);
    }

    /**
     * 版本更新处理
     */
    private static void onVersionUpgrade() {
        String[] renames = {
                "white-host",
                "black-host",
                "exclude-headers",
        };
        String[] renameTargets = {
                WordlistManager.KEY_HOST_ALLOWLIST,
                WordlistManager.KEY_HOST_BLOCKLIST,
                WordlistManager.KEY_REMOVE_HEADERS,
        };
        for (int i = 0; i < renames.length; i++) {
            String name = renames[i];
            String path = sWordlistDir + File.separator + name;
            // 如果目录存在，重命名为新目录名
            if (FileUtils.isDir(path)) {
                String newName = renameTargets[i];
                String newPath = sWordlistDir + File.separator + newName;
                File f = new File(path);
                boolean state = f.renameTo(new File(newPath));
                if (state) {
                    Logger.debug("rename %s to %s OK!", path, newPath);
                }
            }
        }
    }

    /**
     * 初始化字典存放目录
     */
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

    /**
     * 初始化默认字典配置
     *
     * @param key        配置 key
     * @param resName    资源名
     * @param reInitFile 是否重新初始化文件
     */
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

    /**
     * 检查无效配置
     */
    private static void onCheckInvalidConfig() {
        Field[] fields = WordlistManager.class.getDeclaredFields();
        for (Field field : fields) {
            String name = field.getName();
            if (!name.startsWith("KEY_")) {
                continue;
            }
            try {
                String key = (String) field.get(null);
                boolean exists = wordlistFileExists(key);
                // 配置的字典文件存在，判定配置有效
                if (exists) {
                    continue;
                }
                // 配置无效，切换一个配置。先列出当前配置的字典列表
                List<String> itemList = WordlistManager.getItemList(key);
                // 如果字典列表为空，删除当前配置 key（删除配置 key 后，会重新初始化）
                if (itemList.isEmpty()) {
                    Config.removeKey(key);
                    continue;
                }
                // 随机取一个配置的字典
                String item = Utils.getRandomItem(itemList);
                // 设置这个字典
                WordlistManager.putItem(key, item);
            } catch (IllegalAccessException e) {
                // ignored
            }
        }
    }

    /**
     * 获取当前使用的字典名
     *
     * @param key 配置 key
     * @return 返回字典名；失败返回：default
     */
    public static String getItem(String key) {
        String item = Config.get(key);
        if (StringUtils.isEmpty(item)) {
            item = "default";
        }
        return item;
    }

    /**
     * 修改当前使用的字典名
     *
     * @param key  配置 key
     * @param item 字典名
     */
    public static void putItem(String key, String item) {
        Config.put(key, item);
    }

    /**
     * 获取字典
     *
     * @param key 配置 key
     * @return 字典数据；失败返回空列表
     */
    public static List<String> getList(String key) {
        String item = getItem(key);
        return getList(key, item);
    }

    /**
     * 获取字典
     *
     * @param key  配置 key
     * @param item 字典名
     * @return 字典数据；失败返回空列表
     */
    public static List<String> getList(String key, String item) {
        checkInit();
        String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
        ArrayList<String> list = FileUtils.readFileToList(path);
        if (list == null) {
            list = new ArrayList<>();
        }
        return list;
    }

    /**
     * 修改字典
     *
     * @param key  配置 key
     * @param list 修改后的内容
     */
    public static void putList(String key, List<String> list) {
        String item = getItem(key);
        putList(key, item, list);
    }

    /**
     * 修改字典
     *
     * @param key  配置 key
     * @param item 字典名
     * @param list 修改后的内容
     */
    public static void putList(String key, String item, List<String> list) {
        checkInit();
        if (list == null) {
            return;
        }
        if (StringUtils.isEmpty(item)) {
            item = "default";
        }
        String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
        String content = StringUtils.join(list, "\n");
        FileUtils.writeFile(path, content);
    }

    /**
     * 创建字典
     *
     * @param key  配置 key
     * @param name 字典名
     */
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

    /**
     * 删除字典
     *
     * @param key  配置 key
     * @param name 字典名
     */
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

    /**
     * 列出配置 key 的所有字典名
     *
     * @param key 配置 key
     * @return 所有字典名
     */
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

    /**
     * 字典文件是否存在
     *
     * @param key 配置 key
     * @return true=存在；false=不存在
     */
    public static boolean wordlistFileExists(String key) {
        String item = getItem(key);
        String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
        return FileUtils.isFile(path);
    }

    /**
     * 检测字典管理器初始化状态
     */
    private static void checkInit() {
        if (StringUtils.isEmpty(sWordlistDir) || !FileUtils.isDir(sWordlistDir)) {
            throw new IllegalArgumentException("WordlistManager no init.");
        }
    }

    public static List<String> getPayload(String item) {
        return getList(WordlistManager.KEY_PAYLOAD, item);
    }

    public static List<String> getHeader() {
        return getList(WordlistManager.KEY_HEADERS);
    }

    public static List<String> getUserAgent() {
        return getList(WordlistManager.KEY_USER_AGENT);
    }

    public static List<String> getHostAllowlist() {
        return getList(WordlistManager.KEY_HOST_ALLOWLIST);
    }

    public static List<String> getHostBlocklist() {
        return getList(WordlistManager.KEY_HOST_BLOCKLIST);
    }

    public static List<String> getRemoveHeaders() {
        return getList(WordlistManager.KEY_REMOVE_HEADERS);
    }
}
