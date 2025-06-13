package burp.vaycore.onescan.common;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.UrlUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * IHttpRequestResponse 接口适配器
 * <p>
 * Created by vaycore on 2023-07-09.
 */
public class HttpReqRespAdapter implements IHttpRequestResponse {

    private IHttpService service;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private String comment;
    private String highlight;

    public static HttpReqRespAdapter from(String url) throws IllegalArgumentException {
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("url is null");
        }
        if (!UrlUtils.isHTTP(url)) {
            throw new IllegalArgumentException(url + " does not include the protocol.");
        }
        try {
            URL u = new URL(url);
            IHttpService service = buildHttpServiceByURL(u);
            String host = UrlUtils.getHostByURL(u);
            byte[] requestBytes = buildRequestBytes(host, UrlUtils.toPQF(u));
            return new HttpReqRespAdapter(service, requestBytes);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Url: " + url + " format error.");
        }
    }

    public static HttpReqRespAdapter from(URL url, IRequestInfo info, String reqPQF, List<String> cookies) {
        IHttpService service = buildHttpServiceByURL(url);
        List<String> headers = info.getHeaders();
        boolean existsCookie = existsCookieByHeader(headers);
        StringBuilder builder = new StringBuilder();
        String host = UrlUtils.getHostByURL(url);
        builder.append("GET ").append(reqPQF).append(" HTTP/1.1").append("\r\n");
        builder.append("Host: ").append(host).append("\r\n");
        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            // 排除 Host 请求头（需要特殊定制）
            if (item.toLowerCase().startsWith("host: ")) {
                continue;
            }
            // 合并请求的 Cookie 值（如果原请求中不存在 Cookie 值，将 Cookie 插入到 2 的位置）
            if (!existsCookie && i == 2) {
                String cookie = mergeCookie(null, cookies);
                if (StringUtils.isNotEmpty(cookie)) {
                    builder.append("Cookie: ").append(cookie).append("\r\n");
                }
            } else if (item.toLowerCase().startsWith("cookie: ")) {
                // 分割 Header 的 name 和 value 值
                String cookieValue = item.split(": ")[1];
                // 分割 Cookie 的 key 和 value 值
                String[] oldCookie = cookieValue.split(";\\s*");
                String cookie = mergeCookie(oldCookie, cookies);
                if (StringUtils.isNotEmpty(cookie)) {
                    builder.append("Cookie: ").append(cookie).append("\r\n");
                }
                continue;
            }
            builder.append(item).append("\r\n");
        }
        builder.append("\r\n");
        byte[] requestBytes = builder.toString().getBytes(StandardCharsets.UTF_8);
        return new HttpReqRespAdapter(service, requestBytes);
    }

    public static HttpReqRespAdapter from(IHttpService service, byte[] requestBytes) {
        return new HttpReqRespAdapter(service, requestBytes);
    }

    /**
     * 检测 Header 列表是否存在 Cookie 字段
     *
     * @param headers Header 列表
     * @return true=存在；false=不存在
     */
    private static boolean existsCookieByHeader(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("cookie: ")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 合并 Cookie 列表
     *
     * @param oldCookies 原请求的 Cookie 列表
     * @param cookies    响应包中的 Cookie 列表
     * @return 返回请求包中的 Cookie 格式
     */
    private static String mergeCookie(String[] oldCookies, List<String> cookies) {
        List<String> result = new ArrayList<>();
        // 处理响应包中 Cookie 列表为空的情况
        if (cookies == null || cookies.isEmpty()) {
            return StringUtils.join(oldCookies, "; ");
        }
        // 合并 Cookie 值
        for (String cookie : cookies) {
            String[] split = cookie.split("=");
            String key = split[0];
            String value = "";
            if (split.length > 1) {
                value = split[1];
            }
            int index = cookieKeyIndexOf(oldCookies, key);
            if (index >= 0) {
                oldCookies[index] = null;
            }
            // 兼容 Shiro 移除 Cookie 的操作
            if (value.equalsIgnoreCase("deleteMe")) {
                continue;
            }
            result.add(cookie);
        }
        // 剩下未移除的，全部添加到列表
        if (oldCookies != null) {
            for (String cookie : oldCookies) {
                if (cookie != null) {
                    result.add(cookie);
                }
            }
        }
        return StringUtils.join(result, "; ");
    }

    /**
     * 查询 CookieKey 在列表中的下标
     *
     * @param cookies   列表实例
     * @param cookieKey Cookie 的 key
     * @return 失败返回 -1
     */
    private static int cookieKeyIndexOf(String[] cookies, String cookieKey) {
        if (cookies == null || cookies.length == 0) {
            return -1;
        }
        for (int i = 0; i < cookies.length; i++) {
            String item = cookies[i];
            if (item != null && item.contains("=")) {
                String key = item.split("=")[0];
                if (key.equals(cookieKey)) {
                    return i;
                }
            }
        }
        return -1;
    }

    private HttpReqRespAdapter() {
        throw new IllegalAccessError("class not support create instance.");
    }

    private HttpReqRespAdapter(IHttpService service, byte[] requestBytes) {
        if (service == null || requestBytes == null) {
            throw new IllegalArgumentException("service or request bytes is null");
        }
        this.service = service;
        this.requestBytes = requestBytes;
        this.responseBytes = new byte[0];
        this.comment = "";
        this.highlight = "";
    }

    private static byte[] buildRequestBytes(String host, String reqPQF) {
        StringBuilder result = buildRequest(host, reqPQF);
        if (StringUtils.isNotEmpty(result)) {
            return result.toString().getBytes(StandardCharsets.UTF_8);
        }
        return new byte[0];
    }

    private static StringBuilder buildRequest(String host, String reqPQF) {
        return new StringBuilder()
                .append("GET ").append(reqPQF).append(" HTTP/1.1").append("\r\n")
                .append("Host: ").append(host).append("\r\n")
                .append("Accept: ").append("text/html,application/xhtml+xml,")
                .append("application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;")
                .append("q=0.8,application/signed-exchange;v=b3;q=0.9").append("\r\n")
                .append("Accept-Language: ").append("zh-CN,zh;q=0.9,en;q=0.8").append("\r\n")
                .append("Accept-Encoding: ").append("gzip, deflate").append("\r\n")
                .append("Cache-Control: ").append("max-age=0").append("\r\n")
                .append("\r\n");
    }

    private static IHttpService buildHttpServiceByURL(URL url) {
        return new IHttpService() {
            @Override
            public String getHost() {
                return url.getHost();
            }

            @Override
            public int getPort() {
                String protocol = getProtocol();
                int port = url.getPort();
                if (port == -1) {
                    port = protocol.equals("https") ? 443 : 80;
                }
                return port;
            }

            @Override
            public String getProtocol() {
                return url.getProtocol();
            }
        };
    }

    @Override
    public byte[] getRequest() {
        return this.requestBytes;
    }

    @Override
    public void setRequest(byte[] bytes) {
        this.requestBytes = bytes;
    }

    @Override
    public byte[] getResponse() {
        return this.responseBytes;
    }

    @Override
    public void setResponse(byte[] bytes) {
        this.responseBytes = bytes;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String s) {
        this.comment = s;
    }

    @Override
    public String getHighlight() {
        return this.highlight;
    }

    @Override
    public void setHighlight(String s) {
        this.highlight = s;
    }

    @Override
    public IHttpService getHttpService() {
        return this.service;
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        this.service = iHttpService;
    }
}
