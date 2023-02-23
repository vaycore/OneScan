package burp.vaycore.onescan.common;

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

/**
 * 输入框数字过滤器
 * <p>
 * Created by vaycore on 2023-02-23.
 */
public class NumberFilter extends KeyAdapter {

    @Override
    public void keyTyped(KeyEvent e) {
        int key = e.getKeyChar();
        if (key < KeyEvent.VK_0 || key > KeyEvent.VK_9) {
            e.consume();
        }
    }
}
