package burp.vaycore.onescan.ui.payloadlist.rule;

import burp.vaycore.onescan.ui.payloadlist.PayloadRule;

/**
 * 添加前缀
 * <p>
 * Created by vaycore on 2022-09-02.
 */
public class AddPrefix extends PayloadRule {

    @Override
    public String ruleName() {
        return "Add prefix";
    }

    @Override
    public int paramCount() {
        return 1;
    }

    @Override
    public String paramName(int index) {
        return "Prefix";
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        return "Add Prefix: " + values[0];
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        return values[0] + content;
    }
}
