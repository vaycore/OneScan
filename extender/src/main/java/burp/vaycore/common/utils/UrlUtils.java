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
     * 检测 URL 字符串是否为 HTTP 协议
     *
     * @param url URL 字符串
     * @return true=是；false=否
     */
    public static boolean isHTTP(String url) {
        if (StringUtils.isEmpty(url)) {
            return false;
        }
        return url.startsWith("http://") || url.startsWith("https://");
    }

    /**
     * 将 URL 拼接 path + query 值，输出字符串
     * <p>示例格式：/api/v1、/api/v1/get?a=1&b=2</p>
     *
     * @param url URL 实例
     * @return 示例格式字符串
     */
    public static String toPQ(URL url) {
        String path = url.getPath();
        String query = url.getQuery();
        return concatPQF(path, query, null);
    }

    /**
     * 将 URL 拼接 path + query + fragment 值，输出字符串
     * <p>示例格式：/api/v1、/api/v1/get?a=1&b=2、/api/v1/get?a=1#xxx</p>
     *
     * @param url URL 实例
     * @return 示例格式字符串
     */
    public static String toPQF(URL url) {
        String path = url.getPath();
        String query = url.getQuery();
        String fragment = url.getRef();
        return concatPQF(path, query, fragment);
    }

    /**
     * 拼接 path + query + fragment 值，输出字符串
     * <p>示例格式：/api/v1、/api/v1/get?a=1&b=2、/api/v1/get?a=1#xxx</p>
     *
     * @param path     路径
     * @param query    参数
     * @param fragment 切片
     * @return URI 格式字符串
     */
    private static String concatPQF(String path, String query, String fragment) {
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
     * @param url URL 字符串
     * @return 解析异常返回null
     */
    public static URL parseURL(String url) {
        return parseURL(url, null);
    }

    /**
     * 将 url 字符串解析为 URL 实例
     *
     * @param url      URL 字符串
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
     * 通过 URL 实例，获取 Host 地址（例如：x.x.x.x、x.x.x.x:8080）
     *
     * @param url URL 实例
     * @return 返回 Host 地址
     */
    public static String getHostByURL(URL url) {
        String host = url.getHost();
        int port = url.getPort();
        if (Utils.isIgnorePort(port)) {
            return host;
        }
        return host + ":" + port;
    }

    /**
     * 通过 URL 实例，获取请求的 Host 地址（http://x.x.x.x、http://x.x.x.x:8080）
     *
     * @param url URL 实例
     * @return 返回请求的 Host 地址
     */
    public static String getReqHostByURL(URL url) {
        String protocol = url.getProtocol();
        String host = url.getHost();
        int port = url.getPort();
        if (Utils.isIgnorePort(port)) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    /**
     * 解析重定向目标
     *
     * @param originUrl 原请求 URL 实例
     * @param location  响应头 Location 值
     */
    public static URL parseRedirectTargetURL(URL originUrl, String location) {
        if (originUrl == null || StringUtils.isEmpty(location)) {
            return null;
        }
        URL url = parseLocationToURL(originUrl, location);
        if (url == null) {
            return null;
        }
        String reqHost = getReqHostByURL(url);
        String path = url.getPath();
        String canonicalPath = getUrlCanonicalPath(path);
        String query = url.getQuery();
        String fragment = url.getRef();
        String pqf = concatPQF(canonicalPath, query, fragment);
        return parseURL(reqHost + pqf);
    }

    /**
     * 解析响应头中的 Location 值为 URL 实例
     *
     * @param originUrl 原请求 URL 实例
     * @param location  响应头 Location 值
     * @return 解析异常返回 null
     */
    private static URL parseLocationToURL(URL originUrl, String location) {
        if (originUrl == null || StringUtils.isEmpty(location)) {
            return null;
        }
        // 先取原请求 URL 的一些值
        String protocol = originUrl.getProtocol();
        String reqHost = getReqHostByURL(originUrl);
        String path = originUrl.getPath();
        String parentPath = getUrlParentPath(path);
        // 根据响应的 Location 格式进行处理：
        // 绝对路径：http://x.x.x.x/x.html、https://x.x.x.x/x.html
        if (isHTTP(location)) {
            return parseURL(location);
        }
        // 协议相对路径：//x.x.x.x/path/to
        if (location.startsWith("//") && !location.startsWith("///")) {
            String url = protocol + ":" + location;
            return parseURL(url);
        }
        // 相对路径：/path/to/x.html、///path/to/x.html
        if (location.startsWith("/")) {
            String url = reqHost + location;
            return parseURL(url);
        }
        // 相对路径：../path/to/x.html、./path/to/x.html
        if (location.startsWith("../") || location.startsWith("./")) {
            String newUrl = reqHost + parentPath + location;
            return parseURL(newUrl);
        }
        // 参数：?name=value
        if (location.startsWith("?")) {
            String newUrl = reqHost + path + location;
            return parseURL(newUrl);
        }
        // 其他未知格式，直接拼接当前请求目录：
        String result = reqHost + parentPath + location;
        return parseURL(result);
    }

    /**
     * 获取 URL 规范化路径
     *
     * @param path 路径
     * @return 规范化路径
     */
    private static String getUrlCanonicalPath(String path) {
        if (StringUtils.isEmpty(path)) {
            return "/";
        }
        // 不包含跳转，不需要规范化路径
        if (!path.contains("/.") && !path.contains("/..")) {
            return path;
        }
        // 将 '/./' 替换为 '/' 符号
        while (path.contains("/./")) {
            path = path.replace("/./", "/");
        }
        // 处理结尾的目录跳转
        if (path.endsWith("/.")) {
            path = path.substring(0, path.length() - 2) + "/";
        }
        // 处理 '/../' 目录跳转
        while (path.contains("/../")) {
            int start = path.indexOf("/../");
            if (start == 0) {
                path = "/" + path.substring(4);
                continue;
            }
            // 不是前缀，分隔一波（加 1 是因为需要加上 '/' 符号的位置）
            String left = path.substring(0, start + 1);
            String leftParentPath = getUrlParentPath(left);
            String rightPath = path.substring(start + 4);
            path = leftParentPath + rightPath;
        }
        // 处理结尾的目录跳转
        if (path.endsWith("/..")) {
            path = path.substring(0, path.length() - 3);
            path = getUrlParentPath(path);
        }
        return path;
    }

    /**
     * 获取 URL 父目录（例如：'/path/to/x.html' -> '/path/to/' ）
     *
     * @param path 路径
     * @return 父目录
     */
    private static String getUrlParentPath(String path) {
        // 检测传入的值，不符合要求，直接返回默认值
        if (StringUtils.isEmpty(path) || !path.contains("/") || path.equals("/")) {
            return "/";
        }
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path.substring(0, path.lastIndexOf("/") + 1);
    }
}
