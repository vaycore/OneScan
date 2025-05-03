package burp.vaycore.common.helper;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据表格组件 Item 加载器
 * <p>
 * Created by vaycore on 2024-04-13.
 */
public class DataTableItemLoader<T> {

    private static final int NO_DATA_STOP_MILLIS = 10000;
    private static final int MAX_DATA_QUEUE_SIZE = 1000;

    private OnDataItemLoadEvent<T> mOnDataItemLoadEvent;
    private final long mInitialDelay;
    private final long mPeriod;
    private final TimeUnit mTimeUnit;
    private final long mPeriodMillis;
    private ScheduledExecutorService mExecutor;
    private final AtomicLong mStopMillis;
    private final long mMinBatchSize;
    private final long mMaxBatchSize;
    private final ConcurrentLinkedQueue<T> mDataQueue;

    public DataTableItemLoader(long period) {
        this(period, TimeUnit.MILLISECONDS);
    }

    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long period) {
        this(event, period, TimeUnit.MILLISECONDS);
    }

    public DataTableItemLoader(long period, TimeUnit unit) {
        this(null, period, unit);
    }

    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long period, TimeUnit unit) {
        this(event, 0, period, unit);
    }

    public DataTableItemLoader(long initialDelay, long period) {
        this(initialDelay, period, TimeUnit.MILLISECONDS);
    }

    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long initialDelay, long period) {
        this(event, initialDelay, period, TimeUnit.MILLISECONDS);
    }

    public DataTableItemLoader(long initialDelay, long period, TimeUnit unit) {
        this(null, initialDelay, period, unit);
    }

    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long initialDelay, long period, TimeUnit unit) {
        if (period <= 0) {
            throw new IllegalArgumentException("Period must be greater than 0");
        }
        this.mOnDataItemLoadEvent = event;
        this.mInitialDelay = initialDelay;
        this.mPeriod = period;
        this.mTimeUnit = unit;
        this.mPeriodMillis = mTimeUnit.toMillis(mPeriod);
        this.mStopMillis = new AtomicLong(System.currentTimeMillis());
        this.mMinBatchSize = mPeriodMillis;
        this.mMaxBatchSize = (long) (mMinBatchSize * 1.6);
        this.mDataQueue = new ConcurrentLinkedQueue<>();
    }

    private void start() {
        if (isRunning()) {
            return;
        }
        mExecutor = Executors.newSingleThreadScheduledExecutor();
        mExecutor.scheduleAtFixedRate(this::run, mInitialDelay, mPeriod, mTimeUnit);
        Logger.debug("DataTableItemLoader started");
    }

    private void stop() {
        if (!isRunning()) {
            return;
        }
        mExecutor.shutdownNow();
        Logger.debug("DataTableItemLoader stopped");
    }

    public void flush() {
        // 取出所有队列数据，添加到列表
        List<T> temps = new ArrayList<>();
        while (!mDataQueue.isEmpty()) {
            T item = mDataQueue.poll();
            temps.add(item);
        }
        invokeOnDataItemLoadEvent(temps);
        temps.clear();
        Logger.debug("DataTableItemLoader flushed");
    }

    private synchronized void restart() {
        stop();
        start();
    }

    private boolean isRunning() {
        return mExecutor != null && !mExecutor.isShutdown();
    }

    private void run() {
        if (mDataQueue.isEmpty()) {
            long stopMillis = System.currentTimeMillis() - mStopMillis.get();
            // 限制时间内无数据，停止计时器
            if (stopMillis >= NO_DATA_STOP_MILLIS) {
                Logger.debug("DataTableItemLoader no data, stopping...");
                stop();
            }
            return;
        }
        long batchSize = Utils.nextLong(mMinBatchSize, mMaxBatchSize);
        int counter = 0;
        // 取出队列的数据
        ArrayList<T> temps = new ArrayList<>();
        while (counter < batchSize && !mDataQueue.isEmpty()) {
            T data = mDataQueue.poll();
            temps.add(data);
            counter++;
        }
        invokeOnDataItemLoadEvent(temps);
        temps.clear();
    }

    public void pushItem(T item) {
        mDataQueue.offer(item);
        while (mDataQueue.size() > MAX_DATA_QUEUE_SIZE) {
            // 队列数据达到限制，暂停生产，等待消费
            try {
                Thread.sleep(mPeriodMillis);
                Logger.debug("DataTableItemLoader reached max queue size, sleeping...");
            } catch (InterruptedException e) {
                // 线程中断了，加载所有数据
                flush();
                return;
            }
        }
        // 添加数据后，重置计数器
        mStopMillis.set(System.currentTimeMillis());
        // 检测是否已经停止运行
        if (!isRunning()) {
            restart();
        }
    }

    public void setOnDataItemLoadEvent(OnDataItemLoadEvent<T> event) {
        this.mOnDataItemLoadEvent = event;
    }

    private void invokeOnDataItemLoadEvent(List<T> items) {
        if (mOnDataItemLoadEvent != null) {
            mOnDataItemLoadEvent.onDataItemLoaded(items);
        }
    }

    public interface OnDataItemLoadEvent<T> {

        void onDataItemLoaded(List<T> items);
    }
}
