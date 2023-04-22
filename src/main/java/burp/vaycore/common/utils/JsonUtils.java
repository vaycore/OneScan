package burp.vaycore.common.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Json工具类
 * <p>
 * Created by vaycore on 2022-08-30.
 */
public class JsonUtils {

    /**
     * json数据key提取规则
     */
    private static final Pattern sJsonKeyRegex;

    static {
        sJsonKeyRegex = Pattern.compile("\"([^\"]+)\"\\s*:\\s*,?");
    }

    private JsonUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    /**
     * 获取json数据所有key值（不包含重复值）
     *
     * @param json json字符串
     * @return 所有key值
     */
    public static ArrayList<String> findAllKeysByJson(String json) {
        return findAllKeysByJson(json, false);
    }

    /**
     * 获取json数据所有key值
     *
     * @param json      json字符串
     * @param hasRepeat 是否包含重复值
     * @return 所有key值
     */
    public static ArrayList<String> findAllKeysByJson(String json, boolean hasRepeat) {
        ArrayList<String> result = new ArrayList<>();
        if (StringUtils.isEmpty(json)) {
            return result;
        }
        Matcher matcher = sJsonKeyRegex.matcher(json);
        while (matcher.find()) {
            String findKey = matcher.group(1);
            if (StringUtils.isNotEmpty(findKey)) {
                // 是否需要去重
                if (hasRepeat || !result.contains(findKey)) {
                    result.add(findKey);
                }
            }
        }
        return result;
    }

    /**
     * 检测字符串是否为Json格式
     *
     * @param text 字符串
     * @return true=有效；false=无效
     */
    public static boolean hasJson(String text) {
        if (StringUtils.isEmpty(text)) {
            return false;
        }
        text = text.trim();
        // 开关与结尾都是大括号，以对象方式解析
        if (text.startsWith("{") && text.endsWith("}")) {
            Map<String, Object> map = GsonUtils.toMap(text);
            return map != null && !map.isEmpty();
        }
        // 开关与结尾都是中括号，以数组方式解析
        if (text.startsWith("[") && text.endsWith("]")) {
            List<Object> list = GsonUtils.toList(text, Object.class);
            return list != null && !list.isEmpty();
        }
        return false;
    }
}
