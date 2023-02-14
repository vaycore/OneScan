package burp.vaycore.onescan.ui.base;

import javax.swing.*;

/**
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public abstract class BaseTab extends JPanel {

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
}
