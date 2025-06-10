package burp.vaycore.common.utils;

import java.net.MalformedURLException;
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
     * @param url URL 实例
     * @return URI 格式字符串
     */
    public static String toURI(URL url) {
        String path = url.getPath();
        String query = url.getQuery();
        String fragment = url.getRef();
        return concatURI(path, query, fragment);
    }

    /**
     * 拼接 URI 格式字符串
     * <p>示例格式：/api/v1、/api/v1/get?a=1&b=2、/api/v1/get?a=1#xxx</p>
     *
     * @param path     路径
     * @param query    参数
     * @param fragment 切片
     * @return URI 格式字符串
     */
    private static String concatURI(String path, String query, String fragment) {
        StringBuilder result = new StringBuilder(path);
        if (StringUtils.isEmpty(path)) {
            result.append("/");
        }
        if (StringUtils.isNotEmpty(query)) {
            result.append("?").append(query);
        }
        if (StringUtils.isNotEmpty(fragment)) {
            result.append("#").append(fragment);
        }
        return result.toString();
    }

    /**
     * 将 url 字符串解析为 URL 实例
     *
     * @param url url 字符串
     * @return 解析异常返回null
     */
    public static URL parseURL(String url) {
        return parseURL(url, null);
    }

    /**
     * 将 url 字符串解析为 URL 实例
     *
     * @param url      url 字符串
     * @param defValue 解析异常返回的默认值
     * @return 解析异常，返回指定的 defValue 参数值
     */
    public static URL parseURL(String url, URL defValue) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            return defValue;
        }
    }


    /**
     * 通过 URL 实例，获取请求的 Host 地址（http://xxxxxx.com、http://xxxxxx.com:8080）
     *
     * @param url URL 实例
     * @return 返回请求的 Host 地址
     */
    public static String getReqHostByURL(URL url) {
        String protocol = url.getProtocol();
        String host = url.getHost();
        int port = url.getPort();
        if (port < 0 || port == 80 || port == 443 || port > 65535) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }
}
