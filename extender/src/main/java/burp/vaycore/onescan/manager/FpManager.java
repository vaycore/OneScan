package burp.vaycore.onescan.manager;

import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.*;
import burp.vaycore.onescan.common.FpMethodHandler;
import burp.vaycore.onescan.common.OnFpColumnModifyListener;

import java.awt.*;
import java.lang.reflect.Method;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 指纹管理
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpManager {

    public static final String[] sColorNames = {
            "red",
            "orange",
            "yellow",
            "green",
            "cyan",
            "blue",
            "pink",
            "magenta",
            "gray"
    };

    public static final String[] sColorHex = {
            "#FF555D", // red
            "#FFC54D", // orange
            "#FFFF3A", // yellow
            "#00FF45", // green
            "#00FFFF", // cyan
            "#6464FF", // blue
            "#FFC5C7", // pink
            "#FF55FF", // magenta
            "#B4B4B4", // gray
    };

    private static final ConcurrentHashMap<String, List<FpData>> sFpCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, List<FpData>> sFpHistory = new ConcurrentHashMap<>();
    private static final List<OnFpColumnModifyListener> sFpColumnModifyListeners = new ArrayList<>();
    private static String sFilePath;
    private static FpConfig sConfig;

    private FpManager() {
        throw new IllegalAccessError("manager class not support create instance.");
    }

    public static void init(String path) {
        if (StringUtils.isEmpty(path) || !FileUtils.isFile(path)) {
            throw new IllegalArgumentException("fingerprint config file not found.");
        }
        sFilePath = path;
        loadConfig();
    }

    private static void loadConfig() {
        String json = FileUtils.readFileToString(sFilePath);
        if (StringUtils.isEmpty(json)) {
            throw new IllegalArgumentException("fingerprint config is empty.");
        }
        sConfig = GsonUtils.toObject(json, FpConfig.class);
        if (sConfig == null) {
            throw new IllegalArgumentException("fingerprint config parsing failed.");
        }
    }

    /**
     * 检测是否初始化
     */
    private static void checkInit() {
        if (StringUtils.isEmpty(sFilePath) || !FileUtils.isFile(sFilePath) || sConfig == null) {
            throw new IllegalArgumentException("FpManager no init.");
        }
    }

    /**
     * 指纹识别
     *
     * @param reqBytes  HTTP 请求数据包
     * @param respBytes HTTP 响应数据包
     * @return 失败返回空列表
     */
    public static List<FpData> check(byte[] reqBytes, byte[] respBytes) {
        return check(reqBytes, respBytes, true);
    }

    /**
     * 指纹识别
     *
     * @param reqBytes  HTTP 请求数据包
     * @param respBytes HTTP 响应数据包
     * @param useCache  是否使用缓存
     * @return 失败返回空列表
     */
    public static List<FpData> check(byte[] reqBytes, byte[] respBytes, boolean useCache) {
        return check(new FpDSProvider(reqBytes, respBytes), useCache);
    }

    /**
     * 指纹识别
     *
     * @param provider 指纹数据源
     * @param useCache 是否使用缓存
     * @return 失败返回空列表
     */
    public static List<FpData> check(FpDSProvider provider, boolean useCache) {
        checkInit();
        // 提供的数据为空，不继续往下执行
        if (provider == null || provider.isEmpty()) {
            return new ArrayList<>();
        }
        String hashKey = "";
        // 判断是否启用缓存
        if (useCache) {
            hashKey = provider.getCacheKey();
            List<FpData> cacheResults = findCacheByKey(hashKey);
            if (cacheResults != null && !cacheResults.isEmpty()) {
                return cacheResults;
            }
        }
        // 没有指纹数据，不继续往下执行
        if (getCount() == 0) {
            return new ArrayList<>();
        }
        // 匹配指纹数据
        List<FpData> result = getList().parallelStream().filter((item) -> {
            // 可能在扫描过程中存在添加/修改/删除等操作，所以不能使用 item.getRules() 获取的实例进行遍历
            ArrayList<ArrayList<FpRule>> rules = new ArrayList<>(item.getRules());
            List<ArrayList<FpRule>> checkResults = rules.parallelStream().filter((ruleItems) -> {
                if (ruleItems == null || ruleItems.isEmpty()) {
                    return false;
                }
                for (FpRule ruleItem : ruleItems) {
                    // 拿规则数据，获取数据源的数据
                    String dataSource = ruleItem.getDataSource();
                    String field = ruleItem.getField();
                    String method = ruleItem.getMethod();
                    String matchData = provider.getMatchData(dataSource, field);
                    boolean state = invokeFpMethod(method, matchData, ruleItem.getContent());
                    // 里面为 and 运算，只要有一处为 false，表示规则不匹配
                    if (!state) {
                        return false;
                    }
                }
                return true;
            }).collect(Collectors.toList());
            // 外层为 or 运算，只要结果不为空，表示规则匹配
            return !checkResults.isEmpty();
        }).collect(Collectors.toList());
        // 如果启用缓存
        if (useCache) {
            // 将指纹识别结果存放在缓存
            addResultToCache(hashKey, result);
            // 将指纹识别结果添加到历史记录
            String host = provider.getRequestHost();
            addResultToHistory(host, result);
        }
        return result;
    }

    /**
     * 获取当前指纹数据的本地文件路径
     */
    public static String getPath() {
        checkInit();
        return sFilePath;
    }

    /**
     * 获取指纹数据列表
     */
    public static List<FpData> getList() {
        checkInit();
        return new ArrayList<>(sConfig.getList());
    }

    /**
     * 获取指纹数据数量
     */
    public static int getCount() {
        checkInit();
        return sConfig.getListSize();
    }

    /**
     * 添加指纹数据
     *
     * @param data 指纹数据实例
     */
    public static void addItem(FpData data) {
        checkInit();
        sConfig.addListItem(data);
    }

    /**
     * 移除指纹数据
     *
     * @param index 数据下标
     */
    public static void removeItem(int index) {
        checkInit();
        sConfig.removeListItem(index);
    }

    /**
     * 更新指纹数据
     *
     * @param index 下标
     * @param data  指纹数据实例
     */
    public static void setItem(int index, FpData data) {
        checkInit();
        sConfig.setListItem(index, data);
    }

    /**
     * 获取指纹字段列表
     */
    public static List<FpColumn> getColumns() {
        checkInit();
        return new ArrayList<>(sConfig.getColumns());
    }

    /**
     * 根据下标，获取指纹字段 ID 值
     *
     * @return 失败返回null
     */
    public static String getColumnId(int columnIndex) {
        checkInit();
        if (columnIndex < 0 || columnIndex >= getColumnsCount()) {
            return null;
        }
        List<FpColumn> columns = sConfig.getColumns();
        FpColumn column = columns.get(columnIndex);
        return column.getId();
    }

    /**
     * 获取指纹字段名列表
     *
     * @return 失败返回空列表
     */
    public static List<String> getColumnNames() {
        checkInit();
        List<FpColumn> columns = sConfig.getColumns();
        List<String> result = new ArrayList<>(columns.size());
        for (FpColumn column : columns) {
            if (column != null) {
                result.add(column.getName());
            }
        }
        return result;
    }

    /**
     * 获取指纹字段数量
     */
    public static int getColumnsCount() {
        checkInit();
        return sConfig.getColumnsSize();
    }

    /**
     * 添加指纹字段
     *
     * @param column 指纹字段实例
     */
    public static void addColumnsItem(FpColumn column) {
        checkInit();
        sConfig.addColumnsItem(column);
        invokeFpColumnModifyListeners();
    }

    /**
     * 移除指纹字段
     *
     * @param index 数据下标
     */
    public static void removeColumnsItem(int index) {
        checkInit();
        FpColumn column = sConfig.removeColumnsItem(index);
        // 等于 null 表示删除失败
        if (column == null) {
            return;
        }
        // 同步删除指纹数据中的参数和值
        List<FpData> list = getList();
        for (FpData data : list) {
            // 遍历参数列表，过滤需要移除的参数
            List<FpData.Param> removeParams = data.getParams()
                    .stream()
                    .filter(param -> column.getId().equals(param.getK()))
                    .collect(Collectors.toList());
            // 批量移除
            data.getParams().removeAll(removeParams);
        }
        // 保存指纹数据
        sConfig.setList(list);
        invokeFpColumnModifyListeners();
    }

    /**
     * 更新指纹字段
     *
     * @param index 下标
     * @param column  指纹字段实例
     */
    public static void setColumnsItem(int index, FpColumn column) {
        checkInit();
        sConfig.setColumnsItem(index, column);
        invokeFpColumnModifyListeners();
    }

    /**
     * 根据指纹字段 ID 值，查找字段名
     *
     * @param id 字段 ID 值
     * @return 失败返回null
     */
    public static String findColumnNameById(String id) {
        checkInit();
        if (StringUtils.isEmpty(id)) {
            return null;
        }
        List<FpColumn> columns = sConfig.getColumns();
        for (FpColumn column : columns) {
            if (id.equals(column.getId())) {
                return column.getName();
            }
        }
        return null;
    }

    /**
     * 根据指纹字段名，查找字段 ID 值
     *
     * @param name 字段名
     * @return 失败返回null
     */
    public static String findColumnIdByName(String name) {
        checkInit();
        if (StringUtils.isEmpty(name)) {
            return null;
        }
        List<FpColumn> columns = sConfig.getColumns();
        for (FpColumn column : columns) {
            if (name.equals(column.getName())) {
                return column.getId();
            }
        }
        return null;
    }

    /**
     * 生成一个指纹字段实例
     *
     * @return 指纹字段实例
     */
    public static FpColumn generateFpColumn() {
        checkInit();
        String id = Utils.randomString(3);
        String name = findColumnNameById(id);
        if (name != null) {
            return generateFpColumn();
        }
        FpColumn column = new FpColumn();
        column.setId(id);
        return column;
    }

    /**
     * 调用指纹数据匹配方法
     *
     * @param methodName 方法名
     * @param data       数据源
     * @param content    要匹配的内容
     * @return true=匹配；false=不匹配
     */
    private static boolean invokeFpMethod(String methodName, String data, String content) {
        try {
            Method method = FpMethodHandler.class.getDeclaredMethod(methodName, String.class, String.class);
            return (Boolean) method.invoke(null, data, content);
        } catch (Exception var4) {
            return false;
        }
    }

    /**
     * 清除指纹识别缓存
     */
    public static void clearCache() {
        if (!sFpCache.isEmpty()) {
            sFpCache.clear();
        }
    }

    /**
     * 获取指纹识别缓存数量
     */
    public static int getCacheCount() {
        return sFpCache.size();
    }

    /**
     * 根据 key 查找指纹识别缓存
     *
     * @param key 缓存 key
     * @return 失败返回null
     */
    public static List<FpData> findCacheByKey(String key) {
        checkInit();
        if (StringUtils.isEmpty(key) || !sFpCache.containsKey(key)) {
            return null;
        }
        return sFpCache.get(key);
    }

    /**
     * 添加指纹识别结果到缓存
     *
     * @param key     缓存 key
     * @param results 指纹识别结果
     */
    public static void addResultToCache(String key, List<FpData> results) {
        checkInit();
        if (StringUtils.isEmpty(key) || results == null || results.isEmpty()) {
            return;
        }
        if (!sFpCache.containsKey(key)) {
            sFpCache.put(key, new ArrayList<>(results));
        }
    }

    /**
     * 根据 Host 查找指纹识别历史记录
     *
     * @param host 请求头的 Host 数据
     * @return 失败返回null
     */
    public static List<FpData> findHistoryByHost(String host) {
        checkInit();
        if (StringUtils.isEmpty(host) || !sFpHistory.containsKey(host)) {
            return null;
        }
        return sFpHistory.get(host);
    }

    /**
     * 添加指纹识别结果到历史记录
     *
     * @param host    请求头 Host 数据
     * @param results 指纹识别结果
     */
    public static void addResultToHistory(String host, List<FpData> results) {
        checkInit();
        if (StringUtils.isEmpty(host) || results == null || results.isEmpty()) {
            return;
        }
        if (!sFpHistory.containsKey(host)) {
            sFpHistory.put(host, new ArrayList<>(results));
            return;
        }
        List<FpData> dataList = sFpHistory.get(host);
        for (FpData item : results) {
            if (dataList.contains(item)) {
                continue;
            }
            dataList.add(item);
        }
    }

    /**
     * 清除指纹识别历史记录
     */
    public static void clearHistory() {
        if (!sFpHistory.isEmpty()) {
            sFpHistory.clear();
        }
    }

    /**
     * 获取指纹识别历史记录数量
     */
    public static int getHistoryCount() {
        return sFpHistory.size();
    }

    /**
     * 通过颜色名获取颜色实例
     *
     * @param colorName 颜色名
     * @return 颜色实例
     */
    public static Color findColorByName(String colorName) {
        if (StringUtils.isEmpty(colorName)) {
            return null;
        }
        int colorIndex = -1;
        for (int i = 0; i < sColorNames.length; i++) {
            if (sColorNames[i].equals(colorName)) {
                colorIndex = i;
                break;
            }
        }
        if (colorIndex == -1) {
            return null;
        }
        return Color.decode(sColorHex[colorIndex]);
    }

    /**
     * 通过颜色名获取颜色等级
     *
     * @param colorName 颜色名
     * @return 失败返回颜色等级最大值
     */
    public static int findColorLevelByName(String colorName) {
        if (StringUtils.isEmpty(colorName)) {
            return sColorNames.length;
        }
        for (int i = 0; i < sColorNames.length; i++) {
            if (sColorNames[i].equals(colorName)) {
                return i;
            }
        }
        return sColorNames.length;
    }

    /**
     * 添加指纹字段修改监听器
     *
     * @param l 监听器实例
     */
    public static void addOnFpColumnModifyListener(OnFpColumnModifyListener l) {
        checkInit();
        if (sFpColumnModifyListeners.contains(l)) {
            return;
        }
        sFpColumnModifyListeners.add(l);
    }


    /**
     * 移除指纹字段修改监听器
     *
     * @param l 监听器实例
     */
    public static void removeOnFpColumnModifyListener(OnFpColumnModifyListener l) {
        checkInit();
        if (!sFpColumnModifyListeners.contains(l)) {
            return;
        }
        sFpColumnModifyListeners.remove(l);
    }

    /**
     * 清除指纹字段修改监听器
     */
    public static void clearsFpColumnModifyListeners() {
        if (sFpColumnModifyListeners.isEmpty()) {
            return;
        }
        sFpColumnModifyListeners.clear();
    }

    /**
     * 调用指纹字段修改监听器
     */
    private static void invokeFpColumnModifyListeners() {
        checkInit();
        if (sFpColumnModifyListeners.isEmpty()) {
            return;
        }
        for (OnFpColumnModifyListener l : sFpColumnModifyListeners) {
            l.onFpColumnModify();
        }
    }

    /**
     * 颜色升级算法
     *
     * @param colorLevels 颜色等级列表
     * @return 颜色名（示例：{@link FpManager#sColorNames}）；失败返回空字符串
     */
    public static String upgradeColors(Integer... colorLevels) {
        if (colorLevels == null || colorLevels.length == 0) {
            return "";
        }
        return upgradeColors(Arrays.asList(colorLevels));
    }

    /**
     * 颜色升级算法
     *
     * @param colorLevels 颜色等级列表
     * @return 颜色名（示例：{@link FpManager#sColorNames}）；失败返回空字符串
     */
    public static String upgradeColors(List<Integer> colorLevels) {
        if (colorLevels == null || colorLevels.isEmpty()) {
            return "";
        }
        // 统计每个颜色值的出现次数
        Map<Integer, Integer> frequency = new HashMap<>();
        for (int colorLevel : colorLevels) {
            int frequencyValue = frequency.getOrDefault(colorLevel, 0);
            frequency.put(colorLevel, frequencyValue + 1);
        }
        // 计算每个颜色值的最终贡献并取最小值
        int minValue = minFinalColorContribution(frequency);
        // 检测返回的颜色等级是否有效
        if (minValue >= 0 && minValue < sColorNames.length) {
            return sColorNames[minValue];
        }
        // 颜色无效返回空字符串
        return "";
    }

    /**
     * 计算每个颜色值的最终贡献并取最小值
     *
     * @param frequency 颜色出现次数的数据
     * @return 失败返回：{@link Integer#MAX_VALUE}
     */
    private static int minFinalColorContribution(Map<Integer, Integer> frequency) {
        int minIndex = Integer.MAX_VALUE;
        for (Map.Entry<Integer, Integer> entry : frequency.entrySet()) {
            int color = entry.getKey();
            int count = entry.getValue();
            // 计算可升级的次数（log2(count)）
            int steps = (int) (Math.log(count) / Math.log(2));
            int finalColor = color - steps;
            // 确保最终值在有效范围内
            int maxColorIndex = sColorNames.length - 1;
            finalColor = Math.max(0, Math.min(finalColor, maxColorIndex));
            if (finalColor < minIndex) {
                minIndex = finalColor;
            }
        }
        return minIndex;
    }
}
