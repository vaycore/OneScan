package burp.vaycore.common.utils;

import java.net.URL;

/**
 * Url工具类
 * <p>
 * Created by vaycore on 2023-07-12.
 */
public class UrlUtils {

    private UrlUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    /**
     * 转换为路径+Query格式
     *
     * @param url URL 对象
     * @return 响应路径+Query（示例：/api/v1 或者 /api/v1/get?a=1&b=2 格式）
     */
    public static String toPathWithQuery(URL url) {
        String result = url.getPath();
        if (StringUtils.isEmpty(result)) {
            result = "/";
        }
        String query = url.getQuery();
        if (!StringUtils.isEmpty(query)) {
            result += "?" + query;
        }
        return result;
    }

    /**
     * 转换为 URI 格式字符串
     * <p>示例格式：/api/v1、/api/v1/get?a=1&b=2、/api/v1/get?a=1#xxx</p>
     *
     * @param url url 实例
     */
    public static String toURI(URL url) {
        String result = url.getPath();
        if (StringUtils.isEmpty(result)) {
            result = "/";
        }
        String query = url.getQuery();
        if (StringUtils.isNotEmpty(query)) {
            result += "?" + query;
        }
        String fragment = url.getRef();
        if (StringUtils.isNotEmpty(fragment)) {
            result += "#" + fragment;
        }
        return result;
    }
}
