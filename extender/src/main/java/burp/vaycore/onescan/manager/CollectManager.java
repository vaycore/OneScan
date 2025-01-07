package burp.vaycore.onescan.manager;

import burp.vaycore.common.helper.DomainHelper;
import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.ClassUtils;
import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.CollectNode;
import burp.vaycore.onescan.bean.CollectReqResp;
import burp.vaycore.onescan.collect.JsonFieldCollect;
import burp.vaycore.onescan.collect.WebNameCollect;

import javax.swing.*;
import java.io.File;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 数据收集管理
 * <p>
 * Created by vaycore on 2023-12-25.
 */
public class CollectManager {

    /**
     * 数据收集子模块
     */
    private static final Class<?>[] sModules = {
            JsonFieldCollect.class,
            WebNameCollect.class,
    };

    /**
     * 收集数据的内存映射
     */
    private static Map<String, CollectNode> sCollectData;

    /**
     * 去重过滤集合
     */
    private static final Set<String> sRepeatFilter = Collections.synchronizedSet(new HashSet<>());

    private static String sDirPath;
    private static ExecutorService sThreadPool;
    private static CollectNodeListener sCollectNodeListener;
    private static Map<String, ICollectModule> sModuleMap;

    private CollectManager() {
        throw new IllegalAccessError("manager class not support create instance.");
    }

    public static void init(String dirPath) {
        if (StringUtils.isEmpty(dirPath)) {
            throw new IllegalArgumentException("collect directory is empty.");
        }
        if (!FileUtils.exists(dirPath)) {
            FileUtils.mkdirs(dirPath);
        }
        if (!FileUtils.isDir(dirPath)) {
            throw new IllegalArgumentException("collect directory not found.");
        }
        sThreadPool = Executors.newFixedThreadPool(10);
        sModuleMap = new HashMap<>();
        sDirPath = dirPath;
        loadData();
        invokeNodeInitEvent();
    }

    private static void loadData() {
        sCollectData = new HashMap<>();
        // 根节点必须存在
        CollectNode root = createOrGetNode("/", "All");
        File dir = new File(sDirPath);
        // 第一层目录，主要是主域名和 ip 目录名
        File[] parentFiles = dir.listFiles(File::isDirectory);
        if (parentFiles == null || parentFiles.length == 0) {
            return;
        }
        for (File parentFile : parentFiles) {
            // 第二层目录，主要是子域名、ip地址
            File[] hostDirs = parentFile.listFiles(File::isDirectory);
            if (hostDirs == null || hostDirs.length == 0) {
                continue;
            }
            String parentName = parentFile.getName();
            CollectNode parentNode = createOrGetNode("/" + parentName, parentName);
            root.add(parentNode);
            for (File hostDir : hostDirs) {
                String[] dataFiles = hostDir.list();
                if (dataFiles == null || dataFiles.length == 0) {
                    continue;
                }
                String hostName = hostDir.getName();
                CollectNode node = createOrGetNode("/" + parentName + "/" + hostName, hostName);
                parentNode.add(node);
                // 第三层为文件，实际存储收集数据的路径（通过定义的名称读取）
                forEachModule(module -> {
                    // 读取收集的数据（如果文件存在）
                    String moduleName = module.getName();
                    File dataFile = new File(hostDir, moduleName + ".txt");
                    List<String> dataSet;
                    if (!dataFile.exists()) {
                        dataSet = new ArrayList<>();
                    } else {
                        dataSet = FileUtils.readFileToList(dataFile);
                    }
                    // 保存到内存中
                    node.putData(module.getName(), dataSet);
                });
            }
        }
    }

    /**
     * 数据收集方法
     *
     * @param isRequest 是否请求包数据
     * @param host      主机地址（不含端口）
     * @param rawBytes  数据包
     */
    public static void collect(boolean isRequest, String host, byte[] rawBytes) {
        checkInit();
        if (host == null || StringUtils.isEmpty(host.trim())) {
            return;
        }
        // 线程处理数据
        sThreadPool.execute(() -> {
            // 检测此数据是否已经收集
            String tempKey = Utils.md5(rawBytes);
            if (sRepeatFilter.contains(tempKey)) {
                return;
            }
            // 解析数据包，方便调取数据
            CollectReqResp reqResp = new CollectReqResp(isRequest, rawBytes);
            forEachModule(module -> {
                // 收集的数据
                List<String> data = module.doCollect(reqResp);
                if (data == null || data.isEmpty()) {
                    return;
                }
                // 保存数据
                doSaveData(host, module.getName(), data);
            });
            // 添加到去重过滤集合
            sRepeatFilter.add(tempKey);
        });
    }

    /**
     * 保存收集的数据
     *
     * @param host       主机地址（不含端口）
     * @param moduleName 数据收集的子模块名
     * @param data       收集的数据
     */
    private static void doSaveData(String host, String moduleName, List<String> data) {
        CollectNode root = createOrGetNode("/", "All");
        // 按照层级进行分类处理
        String parentName = DomainHelper.getDomain(host, null);
        if (parentName == null) {
            // ip 地址（或者不是域名格式的地址）
            parentName = "ip";
        }
        CollectNode parentNode = createOrGetNode("/" + parentName, parentName);
        root.add(parentNode);
        String nodePath = "/" + parentName + "/" + host;
        // 检测当前节点是否存在，并保存状态
        boolean nodeExists = getNodeByPath(nodePath) != null;
        CollectNode node = createOrGetNode(nodePath, host);
        parentNode.add(node);
        // 节点创建事件
        if (!nodeExists) {
            invokeNodeCreateEvent(nodePath, node);
        }
        List<String> diff = node.putData(moduleName, data);
        if (diff.isEmpty()) {
            return;
        }
        // 拼接成保存路径
        String saveDir = sDirPath + File.separator + parentName + File.separator + host + File.separator;
        if (!FileUtils.exists(saveDir)) {
            FileUtils.mkdirs(saveDir);
        }
        // 保存收集的数据到文件到内存和文件中
        String savePath = saveDir + moduleName + ".txt";
        // 处理写入文件操作
        String content = StringUtils.join(diff, "\n") + "\n";
        FileUtils.writeFile(savePath, content, true);
    }

    /**
     * 遍历数据收集子模块
     *
     * @param callback 回调接口
     */
    public static void forEachModule(ModuleCallback callback) {
        checkInit();
        if (callback == null) {
            return;
        }
        for (Class<?> moduleClz : sModules) {
            ICollectModule module = getModuleByClass(moduleClz);
            if (module != null) {
                callback.onAcceptModule(module);
            }
        }
    }

    /**
     * 根据节点路径，获取节点实例
     *
     * @param nodePath 节点路径
     * @return 不存在返回null
     */
    public static CollectNode getNodeByPath(String nodePath) {
        checkInit();
        if (sCollectData.containsKey(nodePath)) {
            return sCollectData.get(nodePath);
        }
        return null;
    }

    /**
     * 根据节点路径，删除节点实例
     *
     * @param nodePath 节点路径
     */
    public static void delNodeByPath(String nodePath) {
        if (StringUtils.isEmpty(nodePath) || !sCollectData.containsKey(nodePath)) {
            return;
        }
        // 删除对应路径的节点
        CollectNode node = sCollectData.remove(nodePath);
        node.clearNode();
        // 如果是根节点，需要特殊处理
        if (nodePath.equals("/")) {
            // 删除所有节点实例
            sCollectData.clear();
            // 因为根节点必须存在，所以需要创建个新的根节点
            createOrGetNode("/", "All");
        } else {
            // 删除父节点下的当前节点索引
            CollectNode parentNode = node.getParent();
            parentNode.removeNode(node);
            // 删除子节点（如果存在）
            if (!node.isNodesEmpty()) {
                sCollectData.forEach((key, value) -> {
                    // 添加 '/' 后缀，防止误删
                    String suffixNodePath = nodePath + "/";
                    if (key.startsWith(suffixNodePath)) {
                        sCollectData.remove(key);
                    }
                });
            } else {
                // 没有子节点，删除当前父节点
                CollectNode root = createOrGetNode("/", "All");
                root.removeNode(parentNode);
            }
        }
        // 同时删除本地文件
        try {
            String realPath = new File(sDirPath, nodePath).getCanonicalPath();
            if (!realPath.startsWith(sDirPath)) {
                Logger.error("delete node path exception: " + nodePath);
                return;
            }
            FileUtils.deleteFile(realPath);
            // 如果是根节点，需要重新创建个空目录
            if ("/".equals(nodePath)) {
                FileUtils.mkdirs(sDirPath);
            }
        } catch (Exception e) {
            Logger.error("delete node error: " + e.getMessage());
        }
    }

    /**
     * 设置数据收集节点监听器
     *
     * @param l 事件实例
     */
    public static void setCollectNodeListener(CollectNodeListener l) {
        CollectManager.sCollectNodeListener = l;
    }

    /**
     * 调用节点初始化事件
     */
    private static void invokeNodeInitEvent() {
        SwingUtilities.invokeLater(() -> {
            if (CollectManager.sCollectNodeListener != null) {
                CollectManager.sCollectNodeListener.onNodeInit();
            }
        });
    }

    /**
     * 调用节点创建事件
     */
    private static void invokeNodeCreateEvent(String nodePath, CollectNode node) {
        SwingUtilities.invokeLater(() -> {
            if (CollectManager.sCollectNodeListener != null) {
                CollectManager.sCollectNodeListener.onNodeCreate(nodePath, node);
            }
        });
    }

    /**
     * 初始化检测
     */
    private static void checkInit() {
        if (StringUtils.isEmpty(sDirPath) || !FileUtils.isDir(sDirPath) || sCollectData == null) {
            throw new IllegalArgumentException("CollectManager no init.");
        }
    }

    /**
     * 创建或者获取节点（节点路径不存在时，创建新节点）
     *
     * @param nodePath 节点路径
     * @param nodeName 节点名
     * @return 节点实例
     */
    private static CollectNode createOrGetNode(String nodePath, String nodeName) {
        checkInit();
        if (sCollectData.containsKey(nodePath)) {
            return sCollectData.get(nodePath);
        }
        CollectNode node = new CollectNode(nodeName);
        sCollectData.put(nodePath, node);
        return node;
    }

    /**
     * 根据 module 类对象，获取 module 实例
     *
     * @param moduleClz 类对象
     * @return 获取失败返回null
     */
    private static ICollectModule getModuleByClass(Class<?> moduleClz) {
        String clzName = moduleClz.getName();
        ICollectModule module;
        if (sModuleMap.containsKey(clzName)) {
            module = sModuleMap.get(clzName);
        } else {
            module = (ICollectModule) ClassUtils.newObjectByClass(moduleClz);
            if (module == null) {
                return null;
            }
            sModuleMap.put(clzName, module);
        }
        return module;
    }

    /**
     * 清除去重过滤集合
     */
    public static void clearRepeatFilter() {
        if (!sRepeatFilter.isEmpty()) {
            sRepeatFilter.clear();
        }
    }

    /**
     * 获取去重过滤的数量
     */
    public static int getRepeatFilterCount() {
        return sRepeatFilter.size();
    }


    /**
     * 数据收集模块接口
     */
    public interface ICollectModule {

        /**
         * 给收集的数据命名（字符范围：0-9、a-z、A-Z、_、-）
         */
        String getName();

        /**
         * 数据收集业务
         *
         * @param reqResp 数据收集的请求响应实例
         * @return 收集的数据列表
         */
        List<String> doCollect(CollectReqResp reqResp);
    }

    /**
     * 遍历模块的回调接口
     */
    public interface ModuleCallback {
        /**
         * 遍历时调用的方法
         */
        void onAcceptModule(ICollectModule module);
    }

    /**
     * 数据收集节点监听器
     */
    public interface CollectNodeListener {

        /**
         * 节点初始化事件
         */
        void onNodeInit();

        /**
         * 节点创建事件
         *
         * @param nodePath 节点路径
         * @param node     节点实例
         */
        void onNodeCreate(String nodePath, CollectNode node);
    }
}
