package burp.vaycore.onescan.common;

/**
 * 数据修改监听器
 * <p>
 * Created by vaycore on 2022-09-05.
 */
public interface OnDataChangeListener {

    /**
     * 列表数据有修改
     *
     * @param action 通过 setActionCommand(String) 方法设置的值
     */
    void onDataChange(String action);
}
