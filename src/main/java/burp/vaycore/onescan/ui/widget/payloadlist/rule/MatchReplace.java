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
        return String.format("Match [%s] replace with [%s]", values[0], values[1]);
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        String regex = values[0];
        String value = values[1];
        return content.replaceAll(regex, value);
    }
}
