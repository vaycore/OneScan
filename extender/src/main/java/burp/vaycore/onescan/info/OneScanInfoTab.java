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
    private final IMessageEditorController mController;

    private JList<String> mJsonKeyList;

    public OneScanInfoTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller) {
        mHelpers = callbacks.getHelpers();
        mTabPanel = new JTabbedPane();
        mController = controller;
    }

    @Override
    public String getTabCaption() {
        return "OneScan";
    }

    @Override
    public Component getUiComponent() {
        return mTabPanel;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        if (isRequest) {
            return checkReqEnabled(content);
        } else {
            return checkRespEnabled(content);
        }
    }

    /**
     * 检测当前请求是否需要启用信息辅助面板
     *
     * @param content 请求数据包
     * @return true=启用；false=不启用
     */
    private boolean checkReqEnabled(byte[] content) {
        boolean hasEnabled = false;
        // 解析请求包数据
        IRequestInfo info = mHelpers.analyzeRequest(content);
        // 是否存在指纹识别历史记录
        if (FpManager.getHistoryCount() > 0) {
            String host = getRequestHost(info);
            List<FpData> historyResults = FpManager.findHistoryByHost(host);
            hasEnabled = historyResults != null && !historyResults.isEmpty();
        }
        // 如果未启用，检测请求包是否存在指纹识别数据
        if (!hasEnabled) {
            List<FpData> results = FpManager.check(content, mController.getResponse());
            hasEnabled = results != null && !results.isEmpty();
        }
        // 如果未启用，检测请求包中是否包含 JSON 数据格式
        if (!hasEnabled) {
            String body = getReqBody(info, content);
            hasEnabled = JsonUtils.hasJson(body);
        }
        return hasEnabled;
    }

    /**
     * 检测当前响应是否需要启用信息辅助面板
     *
     * @param content 响应数据包
     * @return true=启用；false=不启用
     */
    private boolean checkRespEnabled(byte[] content) {
        boolean hasEnabled = false;
        // 解析响应包数据
        IResponseInfo info = mHelpers.analyzeResponse(content);
        // 检测响应包中是否包含 JSON 数据格式
        String body = getRespBody(info, content);
        hasEnabled = JsonUtils.hasJson(body);
        return hasEnabled;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        mTabPanel.removeAll();
        // 根据当前数据类型，进入数据提取流程
        if (isRequest) {
            handleReqMessage(content);
        } else {
            handleRespMessage(content);
        }
    }

    /**
     * 处理请求信息
     *
     * @param content 数据包
     */
    private void handleReqMessage(byte[] content) {
        // 解析请求包数据
        IRequestInfo info = mHelpers.analyzeRequest(content);
        // 识别请求包的指纹
        List<FpData> results = FpManager.check(content, mController.getResponse());
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
        if (JsonUtils.hasJson(body)) {
            ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
            if (!keys.isEmpty()) {
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        }
    }

    /**
     * 处理响应信息
     *
     * @param content 数据包
     */
    private void handleRespMessage(byte[] content) {
        // 解析响应包数据
        IResponseInfo info = mHelpers.analyzeResponse(content);
        // 提取响应包 Json 字段数据展示
        String body = getRespBody(info, content);
        if (JsonUtils.hasJson(body)) {
            ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
            if (!keys.isEmpty()) {
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        }
    }

    private JPanel newJsonInfoPanel(List<String> keys) {
        JPanel panel = new JPanel(new VLayout());
        mJsonKeyList = new JList<>(new Vector<>(keys));
        UIHelper.setListCellRenderer(mJsonKeyList);
        JScrollPane scrollPane = new JScrollPane(mJsonKeyList);
        panel.add(scrollPane, "1w");
        return panel;
    }

    @Override
    public byte[] getMessage() {
        return new byte[0];
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
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
        // 优先使用从 IHttpService 获取的 Host 值
        String host = getRequestHost();
        if (StringUtils.isNotEmpty(host)) {
            return host;
        }
        if (info == null) {
            return null;
        }
        // 从 HTTP 请求头中获取 Host 值
        List<String> headers = info.getHeaders();
        for (String header : headers) {
            if (header.startsWith("Host: ")) {
                return header.replace("Host: ", "");
            }
        }
        return null;
    }

    /**
     * 通过 IHttpService 实例，获取请求的 Host 值（示例格式：x.x.x.x、x.x.x.x:8080）
     *
     * @return 失败返回null
     */
    private String getRequestHost() {
        IHttpService service = mController.getHttpService();
        if (service == null) {
            return null;
        }
        String host = service.getHost();
        int port = service.getPort();
        if (port < 0 || port == 80 || port == 443 || port > 65535) {
            return host;
        }
        return host + ":" + port;
    }
}
