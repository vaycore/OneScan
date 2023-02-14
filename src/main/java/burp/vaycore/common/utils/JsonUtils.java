package burp.vaycore.common.utils;

import java.util.ArrayList;
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
}
