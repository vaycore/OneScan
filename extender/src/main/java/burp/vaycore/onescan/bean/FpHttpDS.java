package burp.vaycore.onescan.bean;

import burp.vaycore.common.helper.IconHash;
import burp.vaycore.common.utils.Utils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * HTTP数据源
 * <p>
 * Created by vaycore on 2025-05-13.
 */
public abstract class FpHttpDS extends FpDataSource {

    /**
     * 检测请求行格式正则表达式
     */
    private static final Pattern REGEX_REQ_LINE = Pattern.compile("^[A-Z]+\\s+.*?\\s+HTTP/\\d+(?:\\.\\d+)?",
            Pattern.CASE_INSENSITIVE);

    /**
     * 检测状态行格式正则表达式
     */
    private static final Pattern REGEX_RESP_LINE = Pattern.compile("^HTTP/\\d+(?:\\.\\d+)?\\s+\\d+\\s*.*",
            Pattern.CASE_INSENSITIVE);

    private final String firstLine;
    private final String header;
    private final String body;
    private final String bodyMd5;
    private final String bodyHash;
    private final String bodyHex;

    private final int _bodyOffset;
    private final boolean _hasBody;

    public FpHttpDS(byte[] data, Charset charset) {
        super(data, charset);
        String asciiData = new String(data, StandardCharsets.US_ASCII);
        // 解析首行结束位置
        int firstLineEnd = asciiData.indexOf("\r\n");
        if (firstLineEnd <= 0) {
            throw new IllegalArgumentException("Invalid HTTP Data");
        }
        byte[] firstLineBytes = Arrays.copyOfRange(data, 0, firstLineEnd);
        String firstLine = new String(firstLineBytes, charset);
        if (!checkFirstLine(firstLine)) {
            throw new IllegalArgumentException("Invalid HTTP Data");
        }
        this.firstLine = firstLine;
        // 解析 Header 结束位置
        int headerEnd = asciiData.indexOf("\r\n\r\n");
        if (headerEnd <= 0) {
            throw new IllegalArgumentException("Invalid HTTP Data");
        }
        byte[] headerBytes = Arrays.copyOfRange(data, 0, headerEnd);
        this.header = new String(headerBytes, charset);
        // 解析 Body 数据
        int offset = headerEnd + 4;
        this._bodyOffset = offset;
        // 检测 Body 是否没有数据
        if (data.length - offset <= 0) {
            this._hasBody = false;
            this.body = "";
            this.bodyMd5 = "";
            this.bodyHash = "";
            this.bodyHex = "";
            return;
        }
        this._hasBody = true;
        // 获取 Body 字节数据
        byte[] bodyBytes = Arrays.copyOfRange(data, offset, data.length);
        this.body = new String(bodyBytes, charset);
        // 计算 Body MD5 值
        this.bodyMd5 = Utils.md5(bodyBytes);
        // 计算 Body Hash 值
        this.bodyHash = IconHash.hash(bodyBytes);
        // 计算 Body 十六进制（为性能考虑，只取前 100 个字节数据）
        int hexEnd = Math.min(bodyBytes.length, 100);
        byte[] hexBytes = Arrays.copyOfRange(bodyBytes, 0, hexEnd);
        // 将结果转换为大写
        this.bodyHex = Utils.bytesToHex(hexBytes).toUpperCase();
    }

    public String getFirstLine() {
        return firstLine;
    }

    public String getHeader() {
        return header;
    }

    public String getBody() {
        return body;
    }

    public String getBodyMd5() {
        return bodyMd5;
    }

    public String getBodyHash() {
        return bodyHash;
    }

    public String getBodyHex() {
        return bodyHex;
    }

    public int getBodyOffset() {
        return _bodyOffset;
    }

    public boolean hasBody() {
        return _hasBody;
    }

    /**
     * 检测首行（判断 HTTP 数据是否有效）
     *
     * @return true=有效；false=无效
     */
    private boolean checkFirstLine(String firstLine) {
        boolean checkReqLine = REGEX_REQ_LINE.matcher(firstLine).find();
        boolean checkRespLine = REGEX_RESP_LINE.matcher(firstLine).find();
        return checkReqLine || checkRespLine;
    }
}
