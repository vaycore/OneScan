package burp.vaycore.common.utils;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 字符串工具类
 * <p>
 * Created by vaycore on 2022-01-24.
 */
public class StringUtils {

    private StringUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    /**
     * 字符串是否为空
     *
     * @param text 字符串
     * @return true=空；false=不为空
     */
    public static boolean isEmpty(CharSequence text) {
        return text == null ||
                text.length() == 0 ||
                String.valueOf(text).length() == 0;
    }

    /**
     * 字符串是否不为空
     *
     * @param text 字符串
     * @return true=不为空；false=为空
     */
    public static boolean isNotEmpty(CharSequence text) {
        return !isEmpty(text);
    }

    /**
     * 解析字符串为 int 类型
     *
     * @param text 字符串
     * @return 解析失败返回0
     */
    public static int parseInt(String text) {
        return parseInt(text, 0);
    }

    /**
     * 解析字符串为 int 类型
     *
     * @param text     字符串
     * @param defValue 默认值
     * @return 解析失败返回 defValue 参数
     */
    public static int parseInt(String text, int defValue) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return defValue;
        }
    }

    /**
     * 将字符串数组的数据进行拼接
     *
     * @param data      数据
     * @param delimiter 数据间的分隔符
     * @return 拼接完成的字符串
     */
    public static String join(String[] data, String delimiter) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String item : data) {
            if (isNotEmpty(sb)) {
                sb.append(delimiter);
            }
            sb.append(item);
        }
        return sb.toString();
    }

    /**
     * 将字符串 List 集合的数据进行拼接
     *
     * @param data      数据
     * @param delimiter 数据间的分隔符
     * @return 拼接完成的字符串
     */
    public static String join(List<String> data, String delimiter) {
        if (data == null || data.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String item : data) {
            if (isNotEmpty(sb)) {
                sb.append(delimiter);
            }
            sb.append(item);
        }
        return sb.toString();
    }

    /**
     * 检测字符串是否为纯数字
     *
     * @param str 字符串
     * @return true=是；false=否
     */
    public static boolean isNumeric(String str) {
        Pattern pattern = Pattern.compile("\\d+");
        // matches 方法是完全匹配规则才会返回true
        return pattern.matcher(str).matches();
    }

    /**
     * 检测包含内容（忽略大小写）
     * <p>
     * 代码来源：<a href="https://juejin.cn/post/6961359406919319589">参考链接</a>
     *
     * @param src  原字符
     * @param what 包含的内容
     * @return true=包含；false=不包含
     */
    public static boolean containsIgnoreCase(String src, String what) {
        if (StringUtils.isEmpty(what)) {
            // 包含空字符串
            return true;
        }

        final int length = what.length();
        final char firstLo = Character.toLowerCase(what.charAt(0));
        final char firstUp = Character.toUpperCase(what.charAt(0));

        for (int i = src.length() - length; i >= 0; i--) {
            // Quick check before calling the more expensive regionMatches() method:
            final char ch = src.charAt(i);
            if (ch != firstLo && ch != firstUp) {
                continue;
            }
            if (src.regionMatches(true, i, what, 0, length))
                return true;
        }
        return false;
    }
}
