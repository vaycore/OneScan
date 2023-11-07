package burp.vaycore.onescan.ui.widget.payloadlist;

/**
 * Payload数据
 * <p>
 * Created by vaycore on 2022-09-02.
 */
public class PayloadItem {

    private PayloadRule rule;
    private int scope;
    private String ruleType;

    public PayloadRule getRule() {
        return rule;
    }

    public void setRule(PayloadRule payloadRule) {
        if (payloadRule == null) {
            return;
        }
        this.rule = payloadRule;
        this.ruleType = payloadRule.getClass().getSimpleName();
    }

    /**
     * 设置作用域
     *
     * @param scope 作用域（常量：{@link PayloadRule#SCOPE_URL}、{@link PayloadRule#SCOPE_HEADER}、
     *              {@link PayloadRule#SCOPE_BODY}、{@link PayloadRule#SCOPE_REQUEST}，
     *              默认：{@link PayloadRule#SCOPE_URL}）
     */
    public void setScope(int scope) {
        this.scope = scope;
    }

    public int getScope() {
        return scope;
    }

    public String getRuleType() {
        return ruleType;
    }
}
