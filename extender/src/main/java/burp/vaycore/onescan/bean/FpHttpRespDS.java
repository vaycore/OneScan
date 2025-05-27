package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.HtmlUtils;
import burp.vaycore.common.utils.Utils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * HTTP 响应数据源
 * <p>
 * Created by vaycore on 2025-05-13.
 */
public class FpHttpRespDS extends FpHttpDS {


    /**
     * HTTP 响应状态码数据正则表达式
     */
    private static final Pattern REGEX_RESP_STATUS = Pattern.compile("^HTTP/\\d+(?:\\.\\d+)?\\s+(\\d+)\\s*.*",
            Pattern.CASE_INSENSITIVE);

    /**
     * HTTP 响应头 Server 数据正则表达式
     */
    private static final Pattern REGEX_RESP_SERVER = Pattern.compile("Server: (.*)",
            Pattern.CASE_INSENSITIVE);

    /**
     * HTTP 响应日期格式正则表达式
     */
    private static final Pattern REGEX_RESP_DATE = Pattern.compile("(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\\s+" +
            "(0[1-9]|[12]\\d|3[01])\\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+" +
            "\\d{4}\\s+([01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d\\s+GMT", Pattern.CASE_INSENSITIVE);

    private final String status;
    private final String server;
    private final String title;

    public FpHttpRespDS(byte[] data, Charset charset) {
        super(data, charset);
        this.status = fetchRegexResult(REGEX_RESP_STATUS, getFirstLine());
        this.server = fetchRegexResult(REGEX_RESP_SERVER, getHeader());
        this.title = HtmlUtils.findTitleByHtmlBody(data, charset.name());
    }

    @Override
    public String calculateCacheKey() {
        // 响应头包含 Set-Cookie，不计算 Hash 值（不缓存）
        if (getHeader().contains("Set-Cookie")) {
            return null;
        }
        // 只处理响应头的日期相关字符串
        String newHeader = REGEX_RESP_DATE.matcher(getHeader()).replaceAll("");
        // 计算拼接后的 Md5 值
        String mergeValue = newHeader + getBodyMd5();
        return Utils.md5(mergeValue.getBytes(StandardCharsets.UTF_8));
    }

    public String getStatus() {
        return status;
    }

    public String getServer() {
        return server;
    }

    public String getTitle() {
        return title;
    }
}
