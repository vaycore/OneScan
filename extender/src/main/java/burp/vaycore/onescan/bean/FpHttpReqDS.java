package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.Utils;

import java.nio.charset.Charset;
import java.util.regex.Pattern;

/**
 * HTTP 请求数据源
 * <p>
 * Created by vaycore on 2025-05-13.
 */
public class FpHttpReqDS extends FpHttpDS {

    /**
     * 获取请求方法正则表达式
     */
    private static final Pattern REGEX_REQ_METHOD = Pattern.compile("^([A-Z]+)\\s+.*?\\s+HTTP/\\d+(?:\\.\\d+)?",
            Pattern.CASE_INSENSITIVE);

    /**
     * 获取请求 URL 正则表达式
     */
    private static final Pattern REGEX_REQ_URL = Pattern.compile("[A-Z]+\\s+(.*?)\\s+HTTP/",
            Pattern.CASE_INSENSITIVE);

    private final String method;
    private final String url;

    public FpHttpReqDS(byte[] data, Charset charset) {
        super(data, charset);
        this.method = fetchRegexResult(REGEX_REQ_METHOD, getFirstLine());
        this.url = fetchRegexResult(REGEX_REQ_URL, getFirstLine());
    }

    @Override
    public String calculateCacheKey() {
        byte[] dataBytes = getDataBytes();
        return Utils.md5(dataBytes);
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }
}
