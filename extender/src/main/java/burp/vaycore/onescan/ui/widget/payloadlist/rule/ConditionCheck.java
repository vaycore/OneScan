package burp.vaycore.onescan.ui.widget.payloadlist.rule;

import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 条件检查
 * <p>
 * Created by vaycore on 2024-06-06.
 */
public class ConditionCheck extends PayloadRule {

    @Override
    public String ruleName() {
        return L.get("payload_rule.condition_check.name");
    }

    @Override
    public int paramCount() {
        return 1;
    }

    @Override
    public String paramName(int index) {
        if (index == 0) {
            return L.get("payload_rule.condition_check.param.match_regex");
        }
        return "";
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        return L.get("payload_rule.condition_check.describe", values[0]);
    }

    @Override
    public String handleProcess(String content) throws IllegalStateException {
        String[] values = getParamValues();
        String regex = values[0];
        Pattern p = Pattern.compile(regex);
        Matcher matcher = p.matcher(content);
        boolean find = matcher.find();
        if (!find) {
            throw new IllegalStateException("Condition not match!");
        }
        return content;
    }
}
