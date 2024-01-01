package burp.vaycore.onescan.bean;

import java.nio.charset.StandardCharsets;

/**
 * 数据收集的请求响应对象
 * <p>
 * Created by vaycore on 2023-12-31.
 */
public class CollectReqResp {

    private final boolean isRequest;
    private final byte[] mRawBytes;
    private final int mOffset;
    private final String mHeader;
    private final String mBody;

    public CollectReqResp(boolean isRequest, byte[] rawBytes) {
        this.isRequest = isRequest;
        if (rawBytes == null) {
            rawBytes = new byte[0];
        }
        this.mRawBytes = rawBytes;
        String text = new String(rawBytes, StandardCharsets.UTF_8);
        this.mOffset = text.indexOf("\r\n\r\n");
        // 通过偏移值，将请求头，请求体分离
        if (this.mOffset >= 0) {
            this.mHeader = text.substring(0, this.mOffset);
            this.mBody = text.substring(this.mOffset + 4);
        } else {
            this.mHeader = text;
            this.mBody = "";
        }
    }

    public boolean isRequest() {
        return isRequest;
    }

    public byte[] getRawBytes() {
        return mRawBytes;
    }

    public int getOffset() {
        return mOffset;
    }

    public String getHeader() {
        return mHeader;
    }

    public String getBody() {
        return mBody;
    }
}
