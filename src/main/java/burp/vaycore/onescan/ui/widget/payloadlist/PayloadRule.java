package burp.vaycore.onescan.ui.widget.payloadlist;

import burp.vaycore.common.utils.StringUtils;

/**
 * 规则接口
 * <p>
 * Created by vaycore on 2022-09-04.
 */
public abstract class PayloadRule {
    /**
     * 对url进行操作
     */
    public static final int SCOPE_URL = 0;

    /**
     * 对请求头进行操作
     */
    public static final int SCOPE_HEADER = 1;

    /**
     * 对整个请求体进行操作
     */
    public static final int SCOPE_BODY = 2;

    /**
     * 对整个请求包进行操作
     */
    public static final int SCOPE_REQUEST = 3;

    /**
     * 参数值列表
     */
    private final String[] paramValues;

    public PayloadRule() {
        paramValues = new String[paramCount()];
    }

    /**
     * 规则名
     *
     * @return 返回一个规则名
     */
    public abstract String ruleName();

    /**
     * 参数个数
     *
     * @return 参数个数
     */
    public abstract int paramCount();

    /**
     * 参数名
     *
     * @param index 参数对应下标
     * @return 参数名
     */
    public abstract String paramName(int index);

    /**
     * 设置参数值
     *
     * @param index 参数对应下标
     * @param value 参数值
     */
    public void setParamValue(int index, String value) {
        if (StringUtils.isEmpty(value)) {
            return;
        }
        paramValues[index] = value;
    }

    /**
     * 获取参数值
     */
    public String[] getParamValues() {
        return paramValues;
    }

    /**
     * 转换为描述信息
     *
     * @return 返回描述信息
     */
    public abstract String toDescribe();

    /**
     * 处理数据
     *
     * @param content 原始数据（作用域不同，原始数据也不同）
     * @return 处理后的数据
     */
    public abstract String handleProcess(String content) throws IllegalStateException;
}
