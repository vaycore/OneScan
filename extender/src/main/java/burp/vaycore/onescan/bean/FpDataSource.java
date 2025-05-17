package burp.vaycore.onescan.bean;

import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 指纹规则数据源
 * <p>
 * Created by vaycore on 2025-05-13.
 */
public abstract class FpDataSource {

    private final String data;
    private final Charset _charset;

    public FpDataSource(byte[] data, Charset charset) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("data is null or empty");
        }
        this.data = new String(data, charset);
        this._charset = charset;
    }

    public String getData() {
        return data;
    }

    public byte[] getDataBytes() {
        return data.getBytes(_charset);
    }

    public Charset getCharset() {
        return _charset;
    }

    /**
     * 计算缓存 key 值
     *
     * @return 不能为空
     */
    public abstract String calculateCacheKey();

    /**
     * 提取正则表达式数据结果
     *
     * @param regex 正则表达式
     * @param data  数据
     * @return 失败返回空字符串
     */
    protected String fetchRegexResult(Pattern regex, String data) {
        Matcher matcher = regex.matcher(data);
        return matcher.find() ? matcher.group(1) : "";
    }
}
