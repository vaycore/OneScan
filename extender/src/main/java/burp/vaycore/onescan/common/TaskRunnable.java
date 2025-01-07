package burp.vaycore.onescan.common;

/**
 * 任务运行类
 *
 * <p>
 * Created by vaycore on 2025-01-07.
 */
public abstract class TaskRunnable implements Runnable {

    /**
     * 扫描任务的 URL
     */
    private final String mUrl;

    public TaskRunnable(String url) {
        this.mUrl = url;
    }

    public String getTaskUrl() {
        return mUrl;
    }
}
