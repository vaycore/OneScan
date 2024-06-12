package burp.vaycore.onescan.manager;

import burp.vaycore.common.helper.IconHash;
import burp.vaycore.common.utils.*;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.bean.FpRule;
import burp.vaycore.onescan.common.FpMethodHandler;

import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 指纹管理
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpManager {

    private static final Pattern sServerRegex = Pattern.compile("Server: (.*)");
    private static String sFilePath;
    private static final ArrayList<FpData> sFpList = new ArrayList<>();
    private static final HashMap<String, List<FpData>> sFpTemp = new HashMap<>();

    private FpManager() {
        throw new IllegalAccessError("manager class not support create instance.");
    }

    public static void init(String path) {
        if (StringUtils.isEmpty(path) || !FileUtils.isFile(path)) {
            throw new IllegalArgumentException("fingerprint config file not found.");
        }
        sFilePath = path;
        loadDataByFile();
    }

    private static void loadDataByFile() {
        if (!sFpList.isEmpty()) {
            sFpList.clear();
        }
        String json = FileUtils.readFileToString(sFilePath);
        if (StringUtils.isEmpty(json)) {
            throw new IllegalArgumentException("fingerprint data is empty.");
        }
        List<FpData> data = GsonUtils.toList(json, FpData.class);
        if (data != null && !data.isEmpty()) {
            sFpList.addAll(data);
        }
    }

    public static ArrayList<FpData> getList() {
        checkInit();
        return sFpList;
    }

    public static String getPath() {
        checkInit();
        return sFilePath;
    }

    public static String getCount() {
        checkInit();
        return String.valueOf(sFpList.size());
    }

    public static void addItem(FpData data) {
        checkInit();
        if (data != null && data.getRules() != null && !data.getRules().isEmpty()) {
            sFpList.add(data);
            writeToFile();
        }
    }

    public static void removeItem(int index) {
        checkInit();
        if (index >= 0 && index < sFpList.size()) {
            sFpList.remove(index);
            writeToFile();
        }
    }

    public static void setItem(int index, FpData data) {
        checkInit();
        if (index >= 0 && index < sFpList.size()) {
            if (data != null && data.getRules() != null && !data.getRules().isEmpty()) {
                sFpList.set(index, data);
                writeToFile();
            }
        }
    }

    public static void clearTemp() {
        if (!sFpTemp.isEmpty()) {
            sFpTemp.clear();
        }
    }

    public static String getTempCount() {
        return String.valueOf(sFpTemp.size());
    }

    public static List<FpData> check(byte[] dataBytes) {
        return check(dataBytes, StandardCharsets.UTF_8, true);
    }

    public static List<FpData> check(byte[] dataBytes, boolean useCache) {
        return check(dataBytes, StandardCharsets.UTF_8, useCache);
    }

    /**
     * 指纹识别
     *
     * @param dataBytes 字节数据
     * @param charset   数据对应的编码（默认 UTF-8）
     * @param useCache  是否启用缓存
     * @return 识别的规则列表（未找到返回空列表）
     */
    public static List<FpData> check(byte[] dataBytes, Charset charset, boolean useCache) {
        checkInit();
        if (dataBytes == null || dataBytes.length == 0) {
            return new ArrayList<>();
        }
        String tempKey = "";
        // 判断是否启用缓存
        if (useCache) {
            tempKey = Utils.md5(dataBytes);
            if (sFpTemp.containsKey(tempKey)) {
                return sFpTemp.get(tempKey);
            }
        }
        // 数据解析
        ArrayList<FpData> list = new ArrayList<>(sFpList);
        String data = new String(dataBytes, charset);
        String header = "";
        String server = "";
        String body = "";
        String title = "";
        String bodyMd5 = "";
        String bodyHash = "";
        if (data.startsWith("HTTP/") && data.contains("\r\n\r\n")) {
            int offset = data.indexOf("\r\n\r\n") + 4;
            header = data.substring(0, offset);
            Matcher matcher = sServerRegex.matcher(header);
            server = matcher.find() ? matcher.group(1) : "";
            body = data.substring(offset);
            byte[] bodyBytes = Arrays.copyOfRange(dataBytes, offset, dataBytes.length);
            title = HtmlUtils.findTitleByHtmlBody(bodyBytes, charset.name());
            bodyMd5 = Utils.md5(bodyBytes);
            bodyHash = IconHash.hash(bodyBytes);
            data = "";
        }
        // 参数引用
        Map<String, String> matchField = new HashMap<>();
        matchField.put(FpRule.MATCH_HEADER, header);
        matchField.put(FpRule.MATCH_SERVER, server);
        matchField.put(FpRule.MATCH_BODY, body);
        matchField.put(FpRule.MATCH_TITLE, title);
        matchField.put(FpRule.MATCH_BODY_MD5, bodyMd5);
        matchField.put(FpRule.MATCH_BODY_HASH, bodyHash);
        matchField.put(FpRule.MATCH_BANNER, data);
        // 匹配指纹规则
        List<FpData> result = list.parallelStream().filter((item) -> {
            ArrayList<ArrayList<FpRule>> rules = item.getRules();
            if (rules == null || rules.isEmpty()) {
                return false;
            }
            List<ArrayList<FpRule>> fpRulesResult = rules.parallelStream().filter((fpRules) -> {
                if (fpRules == null || fpRules.isEmpty()) {
                    return false;
                }
                for (FpRule ruleItem : fpRules) {
                    String method = ruleItem.getMethod();
                    String match = ruleItem.getMatch();
                    String matchData = matchField.get(match);
                    boolean state = invokeFpMethod(method, matchData, ruleItem.getContent());
                    // 里面为 and 运算，只要有一处为 false，表示规则不匹配
                    if (!state) {
                        return false;
                    }
                }
                return true;
            }).toList();
            // 外层为 or 运算，只要结果不为空，表示规则匹配
            return !fpRulesResult.isEmpty();
        }).toList();
        // 如果启用缓存，将指纹识别结果存放在缓存
        if (useCache) {
            sFpTemp.put(tempKey, result);
        }
        return result;
    }

    /**
     * 将指纹数据转换为文本，以逗号分隔
     *
     * @param data 指纹数据
     * @return 文本数据
     */
    public static String listToNames(List<FpData> data) {
        StringBuilder sb = new StringBuilder();
        if (data == null || data.isEmpty()) {
            return sb.toString();
        }
        for (FpData item : data) {
            if (StringUtils.isNotEmpty(sb)) {
                sb.append(",");
            }
            sb.append(item.getName());
        }
        return sb.toString();
    }

    private static void checkInit() {
        if (StringUtils.isEmpty(sFilePath) || !FileUtils.isFile(sFilePath)) {
            throw new IllegalArgumentException("FpManager no init.");
        }
    }

    private static void writeToFile() {
        new Thread(() -> {
            ArrayList<FpData> list = new ArrayList<>(sFpList);
            String json = GsonUtils.toJson(list);
            FileUtils.writeFile(sFilePath, json);
        }).start();
    }

    private static boolean invokeFpMethod(String methodName, String data, String content) {
        try {
            Method method = FpMethodHandler.class.getDeclaredMethod(methodName, String.class, String.class);
            return (Boolean) method.invoke(null, data, content);
        } catch (Exception var4) {
            return false;
        }
    }
}
