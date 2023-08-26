package burp.vaycore.onescan.common;

import burp.vaycore.common.utils.StringUtils;

import javax.swing.text.JTextComponent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

/**
 * 输入框数字过滤器
 * <p>
 * Created by vaycore on 2023-02-23.
 */
public class NumberFilter extends KeyAdapter {

    /**
     * 限制最大输入的位数（如果值是0，或者小于0，表示不限制长度）
     */
    private final int maxDigits;

    public NumberFilter() {
        this(0);
    }

    public NumberFilter(int maxDigits) {
        this.maxDigits = maxDigits;
    }

    @Override
    public void keyTyped(KeyEvent e) {
        int key = e.getKeyChar();
        if (key < KeyEvent.VK_0 || key > KeyEvent.VK_9) {
            e.consume();
        }
        // 如果值是0，或者小于0，不限制长度
        if (this.maxDigits <= 0) {
            return;
        }
        // 被选中场景时的处理
        Object source = e.getSource();
        int length = 0;
        if (source instanceof JTextComponent) {
            length = ((JTextComponent) source).getText().length();
            String selectedText = ((JTextComponent) source).getSelectedText();
            if (StringUtils.isNotEmpty(selectedText)) {
                length = length - selectedText.length();
            }
        }
        // 检测输入是否超过设置的值
        if (length >= this.maxDigits) {
            e.consume();
        }
    }
}
