package burp.vaycore.onescan.ui.widget.payloadlist.rule;

import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;

/**
 * 匹配和替换
 * <p>
 * Created by vaycore on 2022-09-06.
 */
public class MatchReplace extends PayloadRule {

    @Override
    public String ruleName() {
        return "Match/replace";
    }

    @Override
    public int paramCount() {
        return 2;
    }

    @Override
    public String paramName(int index) {
        switch (index) {
            case 0:
                return "Match regex";
            case 1:
                return "Replace with";
        }
        return "";
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        return String.format("Match [%s] replace with [%s]",
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
