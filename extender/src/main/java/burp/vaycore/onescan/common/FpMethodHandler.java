package burp.vaycore.onescan.common;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.StringUtils;

import java.util.regex.Pattern;

/**
 * 指纹规则匹配方法
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpMethodHandler {

    public static boolean equals(String data, String content) {
        return data.equals(content);
    }

    public static boolean notEquals(String data, String content) {
        return !equals(data, content);
    }

    public static boolean iEquals(String data, String content) {
        if (StringUtils.isEmpty(data)) {
            data = "";
        }
        return data.equalsIgnoreCase(content);
    }

    public static boolean iNotEquals(String data, String content) {
        return !iEquals(data, content);
    }

    public static boolean contains(String data, String content) {
        if (StringUtils.isEmpty(data)) {
            data = "";
        }
        return data.contains(content);
    }

    public static boolean notContains(String data, String content) {
        return !contains(data, content);
    }

    public static boolean iContains(String data, String content) {
        if (StringUtils.isEmpty(data)) {
            data = "";
        }
        return StringUtils.containsIgnoreCase(data, content);
    }

    public static boolean iNotContains(String data, String content) {
        return !iContains(data, content);
    }

    public static boolean regex(String data, String content) {
        try {
            Pattern pattern = Pattern.compile(content);
            return pattern.matcher(data).find();
        } catch (Exception var3) {
            Logger.error("Regex compile error: %s", var3.getMessage());
            return false;
        }
    }

    public static boolean notRegex(String data, String content) {
        return !regex(data, content);
    }
}
