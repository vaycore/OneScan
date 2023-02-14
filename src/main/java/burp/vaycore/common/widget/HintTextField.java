package burp.vaycore.common.widget;

import javax.swing.*;
import javax.swing.text.Document;
import java.awt.*;

public class HintTextField extends JTextField {

    private String hintText;

    public HintTextField() {
    }

    public HintTextField(Document doc, String text, int columns) {
        super(doc, text, columns);
    }

    public HintTextField(int columns) {
        super(columns);
    }

    public HintTextField(String text) {
        super(text);
    }

    public HintTextField(String text, int columns) {
        super(text, columns);
    }

    public String getHintText() {
        return hintText;
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);
        if (hintText == null || hintText.length() == 0 || getText().length() > 0) {
            return;
        }
        final Graphics2D g = (Graphics2D) graphics;
        g.setRenderingHint(
                RenderingHints.KEY_ANTIALIASING,
                RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(getDisabledTextColor());
        g.drawString(hintText, getInsets().left, graphics.getFontMetrics()
                .getMaxAscent() + getInsets().top);
    }

    public void setHintText(String s) {
        hintText = s;
    }
}