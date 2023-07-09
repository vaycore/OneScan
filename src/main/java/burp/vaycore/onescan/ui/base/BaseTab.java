package burp.vaycore.onescan.ui.base;

import burp.vaycore.onescan.common.OnTabEventListener;

import javax.swing.*;

/**
 * Tab页面基类
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public abstract class BaseTab extends JPanel {

    private OnTabEventListener mOnTabEventListener;

    public BaseTab() {
        initData();
        initView();
    }

    /**
     * 初始化数据
     */
    protected abstract void initData();

    /**
     * 初始化布局
     */
    protected abstract void initView();

    /**
     * 返回要指定的标题名
     *
     * @return 指定的标题名
     */
    public abstract String getTitleName();



    /**
     * 发送事件
     *
     * @param action 事件action
     */
    protected void sendTabEvent(String action) {
        this.sendTabEvent(action, "");
    }

    /**
     * 发送事件
     *
     * @param action 事件action
     * @param params 事件参数列表
     */
    protected void sendTabEvent(String action, Object... params) {
        if (mOnTabEventListener != null) {
            mOnTabEventListener.onTabEventMethod(action, params);
        }
    }

    /**
     * 设置事件监听
     *
     * @param l 事件监听接口
     */
    public void setOnTabEventListener(OnTabEventListener l) {
        this.mOnTabEventListener = l;
    }
}
