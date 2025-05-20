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

    public static final String[] METHOD_ITEMS = {
            "equals",
            "notEquals",
            "iEquals",
            "iNotEquals",
            "contains",
            "notContains",
            "iContains",
            "iNotContains",
            "regex",
            "notRegex",
            "iRegex",
            "iNotRegex",
    };

    /**
     * 检测相等
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=相等；false=不相等
     */
    public static boolean equals(String data, String content) {
        return data.equals(content);
    }

    /**
     * 检测不相等
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=不相等；false=相等
     */
    public static boolean notEquals(String data, String content) {
        return !equals(data, content);
    }

    /**
     * 检测相等（忽略大小写）
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=相等；false=不相等
     */
    public static boolean iEquals(String data, String content) {
        if (StringUtils.isEmpty(data)) {
            data = "";
        }
        return data.equalsIgnoreCase(content);
    }

    /**
     * 检测不相等（忽略大小写）
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=不相等；false=相等
     */
    public static boolean iNotEquals(String data, String content) {
        return !iEquals(data, content);
    }

    /**
     * 检测包含
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=包含；false=不包含
     */
    public static boolean contains(String data, String content) {
        if (StringUtils.isEmpty(data)) {
            data = "";
        }
        return data.contains(content);
    }

    /**
     * 检测不包含
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=不包含；false=包含
     */
    public static boolean notContains(String data, String content) {
        return !contains(data, content);
    }

    /**
     * 检测包含（忽略大小写）
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=包含；false=不包含
     */
    public static boolean iContains(String data, String content) {
        if (StringUtils.isEmpty(data)) {
            data = "";
        }
        return StringUtils.containsIgnoreCase(data, content);
    }

    /**
     * 检测不包含（忽略大小写）
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=不包含；false=包含
     */
    public static boolean iNotContains(String data, String content) {
        return !iContains(data, content);
    }

    /**
     * 检测正则匹配
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=匹配；false=不匹配
     */
    public static boolean regex(String data, String content) {
        try {
            Pattern pattern = Pattern.compile(content);
            return pattern.matcher(data).find();
        } catch (Exception var3) {
            Logger.error("Regex compile error: %s", var3.getMessage());
            return false;
        }
    }

    /**
     * 检测正则不匹配
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=不匹配；false=匹配
     */
    public static boolean notRegex(String data, String content) {
        return !regex(data, content);
    }

    /**
     * 检测正则匹配（忽略大小写）
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=匹配；false=不匹配
     */
    public static boolean iRegex(String data, String content) {
        try {
            Pattern pattern = Pattern.compile(content, Pattern.CASE_INSENSITIVE);
            return pattern.matcher(data).find();
        } catch (Exception var3) {
            Logger.error("Regex compile error: %s", var3.getMessage());
            return false;
        }
    }

    /**
     * 检测正则不匹配（忽略大小写）
     *
     * @param data    数据源
     * @param content 匹配的内容
     * @return true=不匹配；false=匹配
     */
    public static boolean iNotRegex(String data, String content) {
        return !iRegex(data, content);
    }
}
