package burp.vaycore.common.layout;

import java.awt.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class HLayout extends BaseLayout {
    private int gap = 1;
    private List<Item> items = new ArrayList();
    private boolean usePreferredSize = false;

    public HLayout() {
    }

    public HLayout(int gap2) {
        this.gap = gap2;
    }

    public HLayout(int gap2, boolean usePerferredSize2) {
        this.gap = gap2;
        this.usePreferredSize = usePerferredSize2;
    }

    public void addLayoutComponent(String name, Component comp) {
        Item item = new Item(null);
        item.comp = comp;
        item.constraints = "auto";
        this.items.add(item);
    }

    public void removeLayoutComponent(Component comp) {
        Iterator<Item> iter = this.items.iterator();
        while (iter.hasNext()) {
            if (iter.next().comp == comp) {
                iter.remove();
            }
        }
    }

    public void addLayoutComponent(Component comp, Object constraints) {
        Item item = new Item(null);
        item.comp = comp;
        item.constraints = (String) constraints;
        this.items.add(item);
    }

    public Dimension preferredLayoutSize(Container parent) {
        return new Dimension(30, 30);
    }

    public Dimension minimumLayoutSize(Container parent) {
        return new Dimension(30, 30);
    }

    public Dimension maximumLayoutSize(Container target) {
        return new Dimension(30, 30);
    }

    public void layoutContainer(Container parent) {
        Rectangle rect = new Rectangle(parent.getWidth(), parent.getHeight());
        Insets insets = parent.getInsets();
        rect.x += insets.left;
        rect.y += insets.top;
        rect.width -= insets.left + insets.right;
        rect.height -= insets.top + insets.bottom;
        List<Item> validItems = new ArrayList<>();
        for (Item it : this.items) {
            if (it.comp.isVisible()) {
                validItems.add(it);
            }
        }
        int validSize = rect.width - (this.gap * (validItems.size() - 1));
        int totalSize = 0;
        int totalWeight = 0;
        for (Item it2 : validItems) {
            Dimension preferred = it2.comp.getPreferredSize();
            it2.width = preferred.width;
            it2.height = this.usePreferredSize ? preferred.height : rect.height;
            it2.weight = 0;
            String cstr = it2.constraints;
            if (!(cstr == null || cstr.length() == 0 || cstr.equals("auto"))) {
                if (cstr.endsWith("%")) {
                    it2.width = (validSize * Integer.valueOf(cstr.substring(0, cstr.length() - 1)).intValue()) / 100;
                } else if (cstr.endsWith("w")) {
                    int num = Integer.valueOf(cstr.substring(0, cstr.length() - 1)).intValue();
                    it2.width = 0;
                    it2.weight = num;
                } else if (cstr.endsWith("px")) {
                    it2.width = Integer.valueOf(cstr.substring(0, cstr.length() - 2)).intValue();
                } else {
                    it2.width = Integer.valueOf(cstr).intValue();
                }
            }
            totalSize += it2.width;
            totalWeight += it2.weight;
        }
        if (totalWeight > 0) {
            double unit = ((double) (validSize - totalSize)) / ((double) totalWeight);
            for (Item it3 : validItems) {
                if (it3.weight > 0) {
                    it3.width = (int) (((double) it3.weight) * unit);
                }
            }
        }
        int x = 0;
        for (Item it4 : validItems) {
            int y = (rect.height - it4.height) / 2;
            if (it4.width + x > rect.width) {
                it4.width = rect.width - x;
            }
            if (it4.width > 0) {
                it4.comp.setBounds(rect.x + x, rect.y + y, it4.width, it4.height);
                x = x + it4.width + this.gap;
            } else {
                return;
            }
        }
    }

    private static class Item {
        Component comp;
        String constraints;
        int height;
        int weight;
        int width;

        private Item() {
            this.constraints = "auto";
            this.width = 0;
            this.height = 0;
            this.weight = 0;
        }

        /* synthetic */ Item(Item item) {
            this();
        }
    }
}