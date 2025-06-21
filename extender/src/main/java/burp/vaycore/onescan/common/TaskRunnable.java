package burp.vaycore.onescan.common;

/**
 * 任务运行类
 *
 * <p>
 * Created by vaycore on 2025-01-07.
 */
public abstract class TaskRunnable implements Runnable {

    /**
     * 扫描任务请求的 ID
     */
    private final String mReqId;

    /**
     * 扫描任务的请求来源
     */
    private final String mFrom;

    public TaskRunnable(String reqId, String from) {
        this.mReqId = reqId;
        this.mFrom = from;
    }

    public String getReqId() {
        return mReqId;
    }

    public String getFrom() {
        return mFrom;
    }
}
