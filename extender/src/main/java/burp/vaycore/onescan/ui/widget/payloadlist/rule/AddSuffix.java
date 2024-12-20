package burp.vaycore.onescan.ui.widget.payloadlist.rule;

import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.ui.widget.payloadlist.PayloadRule;

/**
 * 添加后缀
 * <p>
 * Created by vaycore on 2022-09-06.
 */
public class AddSuffix extends PayloadRule {

    @Override
    public String ruleName() {
        return L.get("payload_rule.add_suffix.name");
    }

    @Override
    public int paramCount() {
        return 1;
    }

    @Override
    public String paramName(int index) {
        return L.get("payload_rule.add_suffix.param.suffix");
    }

    @Override
    public String toDescribe() {
        String[] values = getParamValues();
        String paramValue = values[0];
        // 特殊处理 '\r'、'\n' 字符
        if (paramValue.contains("\r")) {
            paramValue = paramValue.replaceAll("\r", "\\\\r");
        }
        if (paramValue.contains("\n")) {
            paramValue = paramValue.replaceAll("\n", "\\\\n");
        }
        return L.get("payload_rule.add_suffix.describe", paramValue);
    }

    @Override
    public String handleProcess(String content) {
        String[] values = getParamValues();
        return content + values[0];
    }
}
