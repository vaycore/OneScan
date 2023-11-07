package burp.vaycore.onescan.ui.widget.payloadlist;

import java.util.ArrayList;

/**
 * Payload Processing数据
 * <p>
 * Created by vaycore on 2023-11-07.
 */
public class ProcessingItem {

    private boolean enabled;
    private String name;
    private ArrayList<PayloadItem> items;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ArrayList<PayloadItem> getItems() {
        return items;
    }

    public void setItems(ArrayList<PayloadItem> items) {
        this.items = items;
    }
}
