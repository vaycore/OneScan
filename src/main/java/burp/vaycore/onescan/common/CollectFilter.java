package burp.vaycore.onescan.common;

import burp.vaycore.onescan.ui.widget.CollectTable;

import javax.swing.*;
import java.util.regex.Pattern;

/**
 * 数据收集过滤器
 * <p>
 * Created by vaycore on 2023-12-23.
 */
public class CollectFilter<T> extends RowFilter<CollectTable.CollectTableModel<T>, Integer> {

    private final boolean isReverse;
    private Pattern mRegex;

    /**
     * 构造方法
     *
     * @param keyword      过滤关键字
     * @param isReverse    是否反向搜索
     * @param isIgnoreCase 是否忽略大小写
     */
    public CollectFilter(String keyword, boolean isReverse, boolean isIgnoreCase) {
        this.isReverse = isReverse;
        try {
            if (isIgnoreCase) {
                this.mRegex = Pattern.compile(keyword, Pattern.CASE_INSENSITIVE);
            } else {
                this.mRegex = Pattern.compile(keyword);
            }
        } catch (Exception e) {
            // ignored
            this.mRegex = null;
        }
    }

    @Override
    public boolean include(Entry<? extends CollectTable.CollectTableModel<T>, ? extends Integer> entry) {
        if (mRegex == null) {
            return true;
        }
        int count = entry.getValueCount();
        boolean find = false;
        for (int i = 0; i < count; i++) {
            String value = entry.getStringValue(i);
            find = mRegex.matcher(value).find();
            if (find) {
                break;
            }
        }
        // 判断是否反向搜索
        if (isReverse) {
            return !find;
        }
        return find;
    }
}
