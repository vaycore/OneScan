package burp.vaycore.common.layout;

import java.awt.*;

/**
 * VerticalFlowLayout is similar to FlowLayout except it lays out components
 * vertically. Extends FlowLayout because it mimics much of the behavior of the
 * FlowLayout class, except vertically. An additional feature is that you can
 * specify a fill to edge flag, which causes the VerticalFlowLayout manager to
 * resize all components to expand to the column width Warning: This causes
 * problems when the main panel has less space that it needs and it seems to
 * prohibit multi-column output. Additionally there is a vertical fill flag,
 * which fills the last component to the remaining height of the container.
 *
 * <p>
 * reference link:<br>
 * https://blog.csdn.net/tiantangqiu/article/details/84829997<br>
 * https://blog.csdn.net/watermelon_csdn/article/details/99710705<br>
 */
public class VFlowLayout extends FlowLayout {

    /**
     * Specify alignment top.
     */
    public static final int TOP = 0;

    /**
     * Specify a middle alignment.
     */
    public static final int MIDDLE = 1;

    /**
     * Specify the alignment to be bottom.
     */
    public static final int BOTTOM = 2;

    int hgap;
    int vgap;
    boolean hfill;
    boolean vfill;

    /**
     * Construct a new VerticalFlowLayout with a middle alignment, and the fill
     * to edge flag set.
     */
    public VFlowLayout() {
        this(TOP, 5, 5, true, false);
    }

    /**
     * Construct a new VerticalFlowLayout with a middle alignment.
     *
     * @param hfill the fill to edge flag
     * @param vfill the vertical fill in pixels.
     */
    public VFlowLayout(boolean hfill, boolean vfill) {
        this(TOP, 5, 5, hfill, vfill);
    }

    /**
     * Construct a new VerticalFlowLayout with a middle alignment.
     *
     * @param align the alignment value
     */
    public VFlowLayout(int align) {
        this(align, 5, 5, true, false);
    }

    /**
     * Construct a new VerticalFlowLayout.
     *
     * @param align the alignment value
     * @param hfill the horizontalfill in pixels.
     * @param vfill the vertical fill in pixels.
     */
    public VFlowLayout(int align, boolean hfill, boolean vfill) {
        this(align, 5, 5, hfill, vfill);
    }

    /**
     * Construct a new VerticalFlowLayout.
     *
     * @param align the alignment value
     * @param hgap  the horizontal gap variable
     * @param vgap  the vertical gap variable
     * @param hfill the fill to edge flag
     * @param vfill true if the panel should vertically fill.
     */
    public VFlowLayout(int align, int hgap, int vgap, boolean hfill, boolean vfill) {
        setAlignment(align);
        this.hgap = hgap;
        this.vgap = vgap;
        this.hfill = hfill;
        this.vfill = vfill;
    }

    /**
     * Returns the preferred dimensions given the components in the target
     * container.
     *
     * @param target the component to lay out
     */
    public Dimension preferredLayoutSize(Container target) {
        synchronized (target.getTreeLock()) {
            Dimension targetSize = new Dimension(0, 0);
            for (int i = 0; i < target.getComponentCount(); i++) {
                Component m = target.getComponent(i);
                if (m.isVisible()) {
                    Dimension d = m.getPreferredSize();
                    targetSize.width = Math.max(targetSize.width, d.width);
                    if (i > 0) {
                        targetSize.height += hgap;
                    }
                    targetSize.height += d.height;
                }
            }
            Insets insets = target.getInsets();
            targetSize.width += insets.left + insets.right + hgap * 2;
            targetSize.height += insets.top + insets.bottom + vgap * 2;
            return targetSize;
        }
    }

    /**
     * Returns the minimum size needed to layout the target container.
     *
     * @param target the component to lay out.
     * @return the minimum layout dimension.
     */
    public Dimension minimumLayoutSize(Container target) {
        synchronized (target.getTreeLock()) {
            Dimension targetSize = new Dimension(0, 0);
            for (int i = 0; i < target.getComponentCount(); i++) {
                Component m = target.getComponent(i);
                if (m.isVisible()) {
                    Dimension d = m.getMinimumSize();
                    targetSize.width = Math.max(targetSize.width, d.width);
                    if (i > 0) {
                        targetSize.height += vgap;
                    }
                    targetSize.height += d.height;
                }
            }
            Insets insets = target.getInsets();
            targetSize.width += insets.left + insets.right + hgap * 2;
            targetSize.height += insets.top + insets.bottom + vgap * 2;
            return targetSize;
        }
    }

    /**
     * Set true to fill vertically.
     *
     * @param vfill true to fill vertically.
     */
    public void setVerticalFill(boolean vfill) {
        this.vfill = vfill;
    }

    /**
     * Returns true if the layout vertically fills.
     *
     * @return true if vertically fills the layout using the specified.
     */
    public boolean getVerticalFill() {
        return vfill;
    }

    /**
     * Set to true to enable horizontally fill.
     *
     * @param hfill true to fill horizontally.
     */
    public void setHorizontalFill(boolean hfill) {
        this.hfill = hfill;
    }

    /**
     * Returns true if the layout horizontally fills.
     *
     * @return true if horizontally fills.
     */
    public boolean getHorizontalFill() {
        return hfill;
    }

    /**
     * places the components defined by first to last within the target
     * container using the bounds box defined.
     *
     * @param target the container.
     * @param x      the x coordinate of the area.
     * @param y      the y coordinate of the area.
     * @param width  the width of the area.
     * @param height the height of the area.
     * @param first  the first component of the container to place.
     * @param last   the last component of the container to place.
     */
    private void placeThem(Container target, int x, int y, int width, int height, int first, int last) {
        int align = getAlignment();
        if (align == MIDDLE) {
            y += height / 2;
        }
        if (align == BOTTOM) {
            y += height;
        }
        for (int i = first; i < last; i++) {
            Component m = target.getComponent(i);
            Dimension md = m.getSize();
            if (m.isVisible()) {
                int px = x + (width - md.width) / 2;
                m.setLocation(px, y);
                y += vgap + md.height;
            }
        }
    }

    /**
     * Lays out the container.
     *
     * @param target the container to lay out.
     */
    public void layoutContainer(Container target) {
        synchronized (target.getTreeLock()) {
            Insets insets = target.getInsets();
            int maxHeight = target.getSize().height - (insets.top + insets.bottom + vgap * 2);
            int maxWidth = target.getSize().width - (insets.left + insets.right + hgap * 2);
            int numComponent = target.getComponentCount();
            int x = insets.left + hgap, y = 0;
            int colw = 0, start = 0;
            for (int i = 0; i < numComponent; i++) {
                Component m = target.getComponent(i);
                if (m.isVisible()) {
                    Dimension d = m.getPreferredSize();
                    // fit last component to remaining height
                    if ((this.vfill) && (i == (numComponent - 1))) {
                        d.height = Math.max((maxHeight - y), m.getPreferredSize().height);
                    }
                    // fit component size to container width
                    if (this.hfill) {
                        m.setSize(maxWidth, d.height);
                        d.width = maxWidth;
                    } else {
                        m.setSize(d.width, d.height);
                    }
                    if (y + d.height > maxHeight) {
                        placeThem(target, x, insets.top + vgap, colw, maxHeight - y, start, i);
                        y = d.height;
                        x += hgap + colw;
                        colw = d.width;
                        start = i;
                    } else {
                        if (y > 0) {
                            y += vgap;
                        }
                        y += d.height;
                        colw = Math.max(colw, d.width);
                    }
                }
            }
            placeThem(target, x, insets.top + vgap, colw, maxHeight - y, start, numComponent);
        }
    }
}