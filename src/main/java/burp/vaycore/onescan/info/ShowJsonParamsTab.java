package burp.vaycore.onescan.info;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.IRequestInfo;
import burp.vaycore.common.utils.JsonUtils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class ShowJsonParamsTab implements IMessageEditorTab {
    private final JPanel mTabbedPane;
    private final IExtensionHelpers mHelpers;
    private JTable jtable;

    public ShowJsonParamsTab(IBurpExtenderCallbacks callbacks) {
        this.mTabbedPane = new JPanel(new BorderLayout());
        this.mHelpers = callbacks.getHelpers();
    }

    public String getTabCaption() {
        return "OneScan";
    }

    public Component getUiComponent() {
        return this.mTabbedPane;
    }

    public boolean isEnabled(byte[] content, boolean isRequest) {
        boolean hasBody = this.hasBody(content);
        return hasBody && JsonUtils.hasJson(this.getBody(content));
    }

    public void setMessage(byte[] content, boolean isRequest) {
        if (isRequest) {
            this.makeTable(content);
        } else {
            this.makeTable(content);
        }
    }

    public void makeTable(byte[] content) {
        this.mTabbedPane.removeAll();
        if (hasBody(content)) {
            String body = this.getBody(content);
            if (JsonUtils.hasJson(body)) {
                ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
                Object[][] jsonParams = new Object[keys.size()][1];
                for (int i = 0; i < keys.size(); ++i) {
                    jsonParams[i][0] = keys.get(i);
                }
                this.jtable = new JTable(jsonParams, new Object[]{"JsonParameters"});
                JScrollPane scrollPane = new JScrollPane(this.jtable);
                this.mTabbedPane.add(scrollPane);
            }
        }
    }

    public byte[] getMessage() {
        return new byte[0];
    }

    public boolean isModified() {
        return false;
    }

    public byte[] getSelectedData() {
        int[] selectRows = this.jtable.getSelectedRows();
        StringBuilder selectData = new StringBuilder();
        for (int rowIndex : selectRows) {
            selectData.append(this.jtable.getValueAt(rowIndex, 0).toString()).append("\n");
        }
        String revData = selectData.reverse().toString().replaceFirst("\n", "");
        StringBuilder retData = new StringBuilder(revData).reverse();
        return this.mHelpers.stringToBytes(retData.toString());
    }

    private boolean hasBody(byte[] content) {
        IRequestInfo info = this.mHelpers.analyzeRequest(content);
        int bodyOffset = info.getBodyOffset();
        int bodySize = content.length - bodyOffset;
        return bodySize > 0;
    }

    private String getBody(byte[] content) {
        IRequestInfo info = this.mHelpers.analyzeRequest(content);
        int bodyOffset = info.getBodyOffset();
        int bodySize = content.length - bodyOffset;
        return new String(content, bodyOffset, bodySize);
    }
}
