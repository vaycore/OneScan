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

    public TaskRunnable(String reqId) {
        this.mReqId = reqId;
    }

    public String getReqId() {
        return mReqId;
    }
}
