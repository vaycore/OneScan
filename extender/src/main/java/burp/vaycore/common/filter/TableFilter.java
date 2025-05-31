package burp.vaycore.common.filter;

import burp.vaycore.common.utils.StringUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

/**
 * 表过滤器
 * <p>
 * Created by vaycore on 2023-02-27.
 */
public class TableFilter<T extends AbstractTableModel> extends RowFilter<T, Object> {

    private final FilterRule rule;

    public TableFilter(FilterRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule is null");
        }
        if (rule.getItems().isEmpty()) {
            throw new IllegalArgumentException("rule condition is null");
        }
        this.rule = rule;
    }

    public FilterRule getRule() {
        return this.rule;
    }

    @Override
    public boolean include(Entry<? extends T, ?> entry) {
        T model = entry.getModel();
        Integer rowIndex = (Integer) entry.getIdentifier();
        int columnIndex = rule.getColumnIndex();
        // 检测是否越界
        if (columnIndex < 0 || columnIndex >= model.getColumnCount() ||
                rowIndex < 0 || rowIndex >= model.getRowCount()) {
            return false;
        }
        Object valueObj = model.getValueAt(rowIndex, columnIndex);
        String value = valueObj == null ? "" : String.valueOf(valueObj);
        ArrayList<FilterRule.Item> items = rule.getItems();
        boolean result = false;
        // 遍历检测规则
        for (int i = 0; i < items.size(); i++) {
            FilterRule.Item item = items.get(i);
            int operate = item.getOperate();
            int logic = item.getLogic();
            boolean check = checkRuleItem(value, item, operate);
            // 只有一个条件，直接返回结果
            if (items.size() == 1) {
                return check;
            }
            // 第一条数据不包含逻辑运算符，直接赋值
            if (logic == 0) {
                result = check;
            } else if (logic == FilterRule.LOGIC_OR) {
                result = result || check;
            } else if (logic == FilterRule.LOGIC_AND) {
                result = result && check;
            }
            // 检测下一条数据的逻辑运算符
            int nextIndex = i + 1;
            if (nextIndex < items.size()) {
                FilterRule.Item nextItem = items.get(nextIndex);
                int nextLogic = nextItem.getLogic();
                // 如果是 AND（&&），当前结果为 false，直接返回结果
                if (nextLogic == FilterRule.LOGIC_AND && !result) {
                    return false;
                }
                // 如果是 OR（||），当前结果为 true，直接返回结果
                if (nextLogic == FilterRule.LOGIC_OR && result) {
                    return true;
                }
            }
        }
        return result;
    }

    /**
     * 检测过滤规则是否与值匹配
     *
     * @param value   检测的值
     * @param item    规则实例
     * @param operate 操作符
     * @return true=匹配；false=不匹配
     */
    private boolean checkRuleItem(String value, FilterRule.Item item, int operate) {
        boolean check = false;
        // 如果是数字的操作符，参数值转换为数字类型进行匹配
        if (operate >= FilterRule.OPERATE_GT && operate <= FilterRule.OPERATE_LT_EQUAL) {
            int left = StringUtils.parseInt(value);
            int right = StringUtils.parseInt(item.getValue());
            switch (operate) {
                case FilterRule.OPERATE_GT:
                    check = left > right;
                    break;
                case FilterRule.OPERATE_GT_EQUAL:
                    check = left >= right;
                    break;
                case FilterRule.OPERATE_LT:
                    check = left < right;
                    break;
                case FilterRule.OPERATE_LT_EQUAL:
                    check = left <= right;
                    break;
            }
        } else {
            // 剩下的操作符都可以使用字符串类型判定
            String right = item.getValue();
            switch (operate) {
                case FilterRule.OPERATE_EQUAL:
                    check = value.equals(right);
                    break;
                case FilterRule.OPERATE_NOT_EQUAL:
                    check = !value.equals(right);
                    break;
                case FilterRule.OPERATE_START:
                    check = value.startsWith(right);
                    break;
                case FilterRule.OPERATE_NOT_START:
                    check = !value.startsWith(right);
                    break;
                case FilterRule.OPERATE_END:
                    check = value.endsWith(right);
                    break;
                case FilterRule.OPERATE_NOT_END:
                    check = !value.endsWith(right);
                    break;
                case FilterRule.OPERATE_INCLUDE:
                    check = value.contains(right);
                    break;
                case FilterRule.OPERATE_NOT_INCLUDE:
                    check = !value.contains(right);
                    break;
            }
        }
        return check;
    }
}
