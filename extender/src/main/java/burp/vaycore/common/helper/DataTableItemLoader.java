package burp.vaycore.common.helper;

import burp.vaycore.common.log.Logger;
import burp.vaycore.common.utils.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据表格组件 Item 加载器
 * <p>
 * Created by vaycore on 2024-04-13.
 */
public class DataTableItemLoader<T> {

    /**
     * 限制时间内无数据，进入停止状态
     */
    private static final int NO_DATA_STOP_MILLIS = 10000;

    /**
     * 队列数据量限制（达到此数据量后，进入等待，直到低于此数据量，继续运行）
     */
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
    private final AtomicBoolean mIsRunning = new AtomicBoolean(false);

    /**
     * 构造方法
     *
     * @param period 每次运行间隔时间（单位：ms）
     */
    public DataTableItemLoader(long period) {
        this(period, TimeUnit.MILLISECONDS);
    }

    /**
     * 构造方法
     *
     * @param event  接收事件的实例
     * @param period 每次运行间隔时间（单位：ms）
     */
    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long period) {
        this(event, period, TimeUnit.MILLISECONDS);
    }

    /**
     * 构造方法
     *
     * @param period 每次运行间隔时间
     * @param unit   参数 period 的时间单位
     */
    public DataTableItemLoader(long period, TimeUnit unit) {
        this(null, period, unit);
    }

    /**
     * 构造方法
     *
     * @param event  接收事件的实例
     * @param period 每次运行间隔时间
     * @param unit   参数 period 的时间单位
     */
    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long period, TimeUnit unit) {
        this(event, 0, period, unit);
    }

    /**
     * 构造方法
     *
     * @param initialDelay 初始运行延迟时间（单位：ms）
     * @param period       每次运行间隔时间（单位：ms）
     */
    public DataTableItemLoader(long initialDelay, long period) {
        this(initialDelay, period, TimeUnit.MILLISECONDS);
    }

    /**
     * 构造方法
     *
     * @param event        接收事件的实例
     * @param initialDelay 初始运行延迟时间（单位：ms）
     * @param period       每次运行间隔时间（单位：ms）
     */
    public DataTableItemLoader(OnDataItemLoadEvent<T> event, long initialDelay, long period) {
        this(event, initialDelay, period, TimeUnit.MILLISECONDS);
    }

    /**
     * 构造方法
     *
     * @param initialDelay 初始运行延迟时间
     * @param period       每次运行间隔时间
     * @param unit         参数 initialDelay 和 period 的时间单位
     */
    public DataTableItemLoader(long initialDelay, long period, TimeUnit unit) {
        this(null, initialDelay, period, unit);
    }

    /**
     * 构造方法
     *
     * @param event        接收事件的实例
     * @param initialDelay 初始运行延迟时间
     * @param period       每次运行间隔时间
     * @param unit         参数 initialDelay 和 period 的时间单位
     */
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

    /**
     * 启动
     */
    private void start() {
        if (isRunning()) {
            return;
        }
        mExecutor = Executors.newSingleThreadScheduledExecutor();
        mExecutor.scheduleAtFixedRate(this::run, mInitialDelay, mPeriod, mTimeUnit);
        mIsRunning.set(true);
        Logger.debug("DataTableItemLoader started");
    }

    /**
     * 停止
     */
    private void stop() {
        if (!isRunning()) {
            return;
        }
        mExecutor.shutdownNow();
        mExecutor = null;
        mIsRunning.set(false);
        Logger.debug("DataTableItemLoader stopped");
    }

    /**
     * 重启
     */
    private synchronized void restart() {
        stop();
        start();
    }

    /**
     * 是否运行中
     *
     * @return true=运行；false=不运行
     */
    private boolean isRunning() {
        return mExecutor != null && mIsRunning.get();
    }

    /**
     * 核心运行方法
     */
    private void run() {
        if (mDataQueue.isEmpty()) {
            long stopMillis = System.currentTimeMillis() - mStopMillis.get();
            // 限制时间内无数据，自动进入停止状态
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

    /**
     * 将数据添加到队列中
     *
     * @param item 数据实例
     */
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

    /**
     * 刷出所有队列数据，全部加载
     */
    public void flush() {
        List<T> temps = new ArrayList<>();
        while (!mDataQueue.isEmpty()) {
            T item = mDataQueue.poll();
            temps.add(item);
        }
        invokeOnDataItemLoadEvent(temps);
        temps.clear();
        Logger.debug("DataTableItemLoader flushed");
    }

    /**
     * 设置事件监听器
     *
     * @param event 接收事件的实例
     */
    public void setOnDataItemLoadEvent(OnDataItemLoadEvent<T> event) {
        this.mOnDataItemLoadEvent = event;
    }

    /**
     * 调用事件
     *
     * @param items 要加载的数据列表
     */
    private void invokeOnDataItemLoadEvent(List<T> items) {
        if (mOnDataItemLoadEvent != null) {
            mOnDataItemLoadEvent.onDataItemLoaded(items);
        }
    }

    /**
     * 数据 Item 加载事件
     *
     * @param <T> 数据 Item 类
     */
    public interface OnDataItemLoadEvent<T> {

        /**
         * 数据 Item 加载事件
         *
         * @param items 要加载的数据列表
         */
        void onDataItemLoaded(List<T> items);
    }
}
