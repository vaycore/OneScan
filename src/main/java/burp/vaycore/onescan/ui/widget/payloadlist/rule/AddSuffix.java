package burp.vaycore.onescan.ui.widget.payloadlist.rule;

import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;

/**
 * 添加后缀
 * <p>
 * Created by vaycore on 2022-09-06.
 */
public class AddSuffix extends PayloadRule {

    @Override
    public String ruleName() {
        return "Add suffix";
    }

    @Override
    public int paramCount() {
        return 1;
    }

    @Override
    public String paramName(int index) {
        return "Suffix";
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        return "Add Suffix: " + values[0];
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        return content + values[0];
    }
}
