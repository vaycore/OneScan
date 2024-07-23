package burp.vaycore.onescan.bean;

import java.io.Serializable;

/**
 * 指纹规则
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpRule implements Serializable {

    /**
     * Header
     */
    public static final String MATCH_HEADER = "header";

    /**
     * Header 中的 Server 值
     */
    public static final String MATCH_SERVER = "server";

    /**
     * Body 数据
     */
    public static final String MATCH_BODY = "body";

    /**
     * Html 标题
     */
    public static final String MATCH_TITLE = "title";

    /**
     * Body 数据的 MD5 值
     */
    public static final String MATCH_BODY_MD5 = "bodyMd5";

    /**
     * Body 数据的 Hash 值
     */
    public static final String MATCH_BODY_HASH = "bodyHash";

    /**
     * 其它协议的 Banner 值
     */
    public static final String MATCH_BANNER = "banner";

    /**
     * 匹配字段
     */
    private String match;

    /**
     * 匹配方法
     */
    private String method;

    /**
     * 匹配内容
     */
    private String content;

    public String getMatch() {
        return this.match;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getContent() {
        return this.content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
