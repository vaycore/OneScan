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
}
