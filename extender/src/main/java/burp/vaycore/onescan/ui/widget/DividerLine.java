package burp.vaycore.onescan.ui.widget;

import javax.swing.*;
import java.awt.*;

/**
 * 分隔线组件
 * <p>
 * Created by vaycore on 2025-06-14.
 */
public class DividerLine extends JPanel {

    /**
     * 默认分隔线颜色（当前主题的颜色配置 key）
     */
    private static final String COLOR_KEY = "SplitPane.shadow";

    /**
     * 默认颜色（无法找到配置 key 时使用）
     */
    private static final Color DEFAULT_COLOR = Color.LIGHT_GRAY;

    /**
     * 横向的分隔线
     *
     * @return 横向分隔线组件
     */
    public static DividerLine h() {
        return new DividerLine(0, 1);
    }

    /**
     * 垂直的分隔线
     *
     * @return 垂直分隔线组件
     */
    public static DividerLine v() {
        return new DividerLine(1, 0);
    }

    private DividerLine() {
        throw new IllegalAccessError("class not support create instance.");
    }

    private DividerLine(int width, int height) {
        setPreferredSize(new Dimension(width, height));
        setOpaque(true);
    }

    public Color getColorByKey() {
        return UIManager.getColor(COLOR_KEY);
    }

    public Color getDefColor() {
        return DEFAULT_COLOR;
    }

    @Override
    public Color getBackground() {
        Color color = getColorByKey();
        if (color != null) {
            return color;
        }
        return getDefColor();
    }
}
