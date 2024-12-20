package burp.vaycore.onescan.ui.widget.payloadlist.rule;

import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;

/**
 * 匹配和替换
 * <p>
 * Created by vaycore on 2022-09-06.
 */
public class MatchReplace extends PayloadRule {

    @Override
    public String ruleName() {
        return L.get("payload_rule.match_replace.name");
    }

    @Override
    public int paramCount() {
        return 2;
    }

    @Override
    public String paramName(int index) {
        switch (index) {
            case 0:
                return L.get("payload_rule.match_replace.param.match_regex");
            case 1:
                return L.get("payload_rule.match_replace.param.replace_with");
        }
        return "";
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        return L.get("payload_rule.match_replace.describe",
                handleParamValue(values[0]), handleParamValue(values[1]));
    }

    /**
     * 特殊处理 '\r'、'\n' 字符
     */
    private String handleParamValue(String paramValue) {
        if (paramValue.contains("\r")) {
            paramValue = paramValue.replaceAll("\r", "\\\\r");
        }
        if (paramValue.contains("\n")) {
            paramValue = paramValue.replaceAll("\n", "\\\\n");
        }
        return paramValue;
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        String regex = values[0];
        String value = values[1];
        return content.replaceAll(regex, value);
    }
}
