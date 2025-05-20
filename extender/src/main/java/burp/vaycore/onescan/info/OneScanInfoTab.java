package burp.vaycore.onescan.info;

import burp.*;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.JsonUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.ui.widget.FpTestResultPanel;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * OneScan 信息辅助面板
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class OneScanInfoTab implements IMessageEditorTab {

    private final IExtensionHelpers mHelpers;
    private final JTabbedPane mTabPanel;
    private JList<String> mJsonKeyList;

    public OneScanInfoTab(IBurpExtenderCallbacks callbacks) {
        mHelpers = callbacks.getHelpers();
        mTabPanel = new JTabbedPane();
    }

    public String getTabCaption() {
        return "OneScan";
    }

    public Component getUiComponent() {
        return mTabPanel;
    }

    public boolean isEnabled(byte[] content, boolean isRequest) {
        boolean hasJsonEnabled = false;
        boolean hasFingerprint = false;
        if (isRequest) {
            // 解析请求包数据
            IRequestInfo info = mHelpers.analyzeRequest(content);
            // 请求包中是否包含 JSON 数据格式
            hasJsonEnabled = hasReqBody(info, content) && JsonUtils.hasJson(getReqBody(info, content));
            // 是否存在指纹识别历史记录
            if (FpManager.getHistoryCount() > 0) {
                String host = getRequestHost(info);
                List<FpData> list = FpManager.findHistoryByHost(host);
                hasFingerprint = list != null && !list.isEmpty();
            } else {
                // 请求包是否存在指纹识别数据
                List<FpData> results = FpManager.check(content, null);
                hasFingerprint = results != null && !results.isEmpty();
            }
        } else {
            // 解析响应包数据
            IResponseInfo info = mHelpers.analyzeResponse(content);
            // 响应包中是否包含 JSON 数据格式
            hasJsonEnabled = hasRespBody(info, content) && JsonUtils.hasJson(getRespBody(info, content));
            // 响应包是否存在指纹识别数据
            List<FpData> results = FpManager.check(null, content);
            hasFingerprint = results != null && !results.isEmpty();
        }
        return hasJsonEnabled || hasFingerprint;
    }

    public void setMessage(byte[] content, boolean isRequest) {
        mTabPanel.removeAll();
        if (isRequest) {
            // 解析请求包数据
            IRequestInfo info = mHelpers.analyzeRequest(content);
            // 识别请求包的指纹
            List<FpData> results = FpManager.check(content, null);
            if (results != null && !results.isEmpty()) {
                mTabPanel.addTab("Fingerprint", new FpTestResultPanel(results));
            }
            // 指纹识别的历史记录
            if (FpManager.getHistoryCount() > 0) {
                String host = getRequestHost(info);
                List<FpData> historyResults = FpManager.findHistoryByHost(host);
                if (historyResults != null && !historyResults.isEmpty()) {
                    mTabPanel.addTab("Fingerprint-History", new FpTestResultPanel(historyResults));
                }
            }
            // 提取请求包 Json 字段数据展示
            String body = getReqBody(info, content);
            boolean hasJsonEnabled = hasReqBody(info, content) && JsonUtils.hasJson(body);
            if (hasJsonEnabled) {
                ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        } else {
            // 解析响应包数据
            IResponseInfo info = mHelpers.analyzeResponse(content);
            // 识别响应包的指纹
            List<FpData> results = FpManager.check(null, content);
            if (results != null && !results.isEmpty()) {
                mTabPanel.addTab("Fingerprint", new FpTestResultPanel(results));
            }
            // 提取响应包 Json 字段数据展示
            String body = getRespBody(info, content);
            boolean hasJsonEnabled = hasRespBody(info, content) && JsonUtils.hasJson(body);
            if (hasJsonEnabled) {
                ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        }
    }

    private JPanel newJsonInfoPanel(ArrayList<String> keys) {
        JPanel panel = new JPanel(new VLayout());
        mJsonKeyList = new JList<>(new Vector<>(keys));
        UIHelper.setListCellRenderer(mJsonKeyList);
        JScrollPane scrollPane = new JScrollPane(mJsonKeyList);
        panel.add(scrollPane, "1w");
        return panel;
    }

    public byte[] getMessage() {
        return new byte[0];
    }

    public boolean isModified() {
        return false;
    }

    public byte[] getSelectedData() {
        int index = mTabPanel.getSelectedIndex();
        String title = mTabPanel.getTitleAt(index);
        List<String> keys;
        if ("Json".equals(title)) {
            keys = mJsonKeyList.getSelectedValuesList();
            return mHelpers.stringToBytes(StringUtils.join(keys, "\n"));
        }
        return new byte[0];
    }

    private boolean hasReqBody(IRequestInfo info, byte[] content) {
        if (info == null || content == null || content.length == 0) {
            return false;
        }
        int bodyOffset = info.getBodyOffset();
        int bodySize = content.length - bodyOffset;
        return bodySize > 0;
    }

    private boolean hasRespBody(IResponseInfo info, byte[] content) {
        if (info == null || content == null || content.length == 0) {
            return false;
        }
        int bodyOffset = info.getBodyOffset();
        int bodySize = content.length - bodyOffset;
        return bodySize > 0;
    }

    private String getReqBody(IRequestInfo info, byte[] content) {
        if (info == null || content == null || content.length == 0) {
            return null;
        }
        int bodyOffset = info.getBodyOffset();
        int bodySize = content.length - bodyOffset;
        return new String(content, bodyOffset, bodySize, StandardCharsets.UTF_8);
    }

    private String getRespBody(IResponseInfo info, byte[] content) {
        if (info == null) {
            return null;
        }
        int bodyOffset = info.getBodyOffset();
        int bodySize = content.length - bodyOffset;
        return new String(content, bodyOffset, bodySize, StandardCharsets.UTF_8);
    }

    private String getRequestHost(IRequestInfo info) {
        if (info == null) {
            return null;
        }
        List<String> headers = info.getHeaders();
        for (String header : headers) {
            if (header.startsWith("Host: ")) {
                return header.replace("Host: ", "");
            }
        }
        return null;
    }
}
