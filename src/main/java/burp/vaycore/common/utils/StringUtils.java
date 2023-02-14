package burp.vaycore.common.utils;

import java.util.ArrayList;

/**
 * 字符串工具类
 * <p>
 * Created by vaycore on 2022-01-24.
 */
public class StringUtils {

    private StringUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static boolean isEmpty(CharSequence text) {
        return text == null ||
                text.length() == 0 ||
                String.valueOf(text).trim().length() == 0;
    }

    public static boolean isNotEmpty(CharSequence text) {
        return !isEmpty(text);
    }

    public static int parseInt(String text) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public static int parseInt(String text, int defValue) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return defValue;
        }
    }

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

    public static String join(ArrayList<String> data, String delimiter) {
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
}
