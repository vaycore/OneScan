package burp.vaycore.common.helper;

/**
 * QPS 限制器
 * <p>
 * Created by vaycore on 2023-02-23.
 */
public class QpsLimiter {

    /**
     * 以每秒的间隔计算
     */
    private static final long PERIOD = 1000;

    /**
     * 接受请求时间窗口
     */
    private final long[] accessTime;

    /**
     * 限制数量，最低为1
     */
    private final int limit;

    /**
     * 限制延时（0 表示不延时）
     */
    private int delay;

    /**
     * 指向最早请求时间的位置
     */
    private int position;

    public QpsLimiter(int limit) {
        this(limit, 0);
    }

    public QpsLimiter(int limit, int delay) {
        if (limit <= 0) {
            throw new IllegalArgumentException("Illegal limit value: " + limit);
        }
        if (delay < 0) {
            delay = 0;
        }
        this.position = 0;
        this.limit = limit;
        this.delay = delay;
        this.accessTime = new long[limit];
    }

    /**
     * 对执行点进行限制
     */
    public synchronized void limit() throws InterruptedException {
        long sleepMillis = 0;
        // 优先使用 delay 限制
        if (this.delay > 0) {
            Thread.sleep(this.delay);
            return;
        }
        long curTime = System.currentTimeMillis();
        if (curTime - this.accessTime[this.position] < PERIOD) {
            // 未达到处理间隔， 计算休眠间隔剩余时间
            sleepMillis = PERIOD - (curTime - this.accessTime[this.position]) + 1;
            curTime = System.currentTimeMillis() + sleepMillis;
        }
        this.accessTime[this.position++] = curTime;
        this.position = this.position % this.limit;
        // 如果为0，没必要 sleep
        if (sleepMillis > 0) {
            Thread.sleep(sleepMillis);
        }
    }
}
