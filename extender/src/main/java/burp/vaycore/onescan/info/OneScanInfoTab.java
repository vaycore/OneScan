package burp.vaycore.onescan.info;

import burp.*;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.JsonUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.manager.FpManager;
import burp.vaycore.onescan.ui.widget.FpTestResultPanel;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OneScan 信息辅助面板
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class OneScanInfoTab implements IMessageEditorTab {

    private final IExtensionHelpers mHelpers;
    private final JTabbedPane mTabPanel;
    private static final Map<String, Boolean> sEnabledMap = new ConcurrentHashMap<>();
    private static final Map<String, MessageCacheBean> sMessageCacheMap = new ConcurrentHashMap<>();

    private JList<String> mJsonKeyList;

    public OneScanInfoTab(IBurpExtenderCallbacks callbacks) {
        mHelpers = callbacks.getHelpers();
        mTabPanel = new JTabbedPane();
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
        String key = Utils.md5(content);
        if (!isRequest && sEnabledMap.containsKey(key)) {
            return sEnabledMap.get(key);
        }
        boolean state = checkEnabled(content, isRequest);
        // 请求包直接返回状态（只缓存响应包数据）
        if (isRequest) {
            return state;
        }
        sEnabledMap.put(key, state);
        return state;
    }

    /**
     * 检测是否启用信息辅助面板
     *
     * @param content   请求/响应数据包
     * @param isRequest 是否请求包
     * @return true=启用；false=不启用
     */
    private boolean checkEnabled(byte[] content, boolean isRequest) {
        boolean hasJsonEnabled = false;
        boolean hasFingerprint = false;
        if (isRequest) {
            // 解析请求包数据
            IRequestInfo info = mHelpers.analyzeRequest(content);
            // 请求包中是否包含 JSON 数据格式
            String body = getReqBody(info, content);
            hasJsonEnabled = JsonUtils.hasJson(body);
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
            String body = getRespBody(info, content);
            hasJsonEnabled = JsonUtils.hasJson(body);
            // 响应包是否存在指纹识别数据
            List<FpData> results = FpManager.check(null, content);
            hasFingerprint = results != null && !results.isEmpty();
        }
        return hasJsonEnabled || hasFingerprint;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        mTabPanel.removeAll();
        String key = Utils.md5(content);
        // 如果响应包存在缓存（只缓存响应包数据）
        if (!isRequest && sMessageCacheMap.containsKey(key)) {
            loadCacheMessage(key);
            return;
        }
        // 无缓存，进入数据提取流程
        if (isRequest) {
            handleReqMessage(content);
        } else {
            handleRespMessage(content, key);
        }
    }

    /**
     * 加载缓存信息
     *
     * @param key 缓存 key
     */
    private void loadCacheMessage(String key) {
        MessageCacheBean bean = sMessageCacheMap.get(key);
        // 指纹识别结果
        List<FpData> results = bean.getResults();
        if (results != null && !results.isEmpty()) {
            mTabPanel.addTab("Fingerprint", new FpTestResultPanel(results));
        }
        // Json 字段
        List<String> jsonKeys = bean.getJsonKeys();
        if (jsonKeys != null && !jsonKeys.isEmpty()) {
            mTabPanel.addTab("Json", newJsonInfoPanel(jsonKeys));
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
    private void handleRespMessage(byte[] content, String key) {
        MessageCacheBean bean = new MessageCacheBean();
        // 解析响应包数据
        IResponseInfo info = mHelpers.analyzeResponse(content);
        // 识别响应包的指纹
        List<FpData> results = FpManager.check(null, content);
        if (results != null && !results.isEmpty()) {
            bean.setResults(results);
            mTabPanel.addTab("Fingerprint", new FpTestResultPanel(results));
        }
        // 提取响应包 Json 字段数据展示
        String body = getRespBody(info, content);
        if (JsonUtils.hasJson(body)) {
            ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
            if (!keys.isEmpty()) {
                bean.setJsonKeys(keys);
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        }
        sMessageCacheMap.put(key, bean);
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

    /**
     * 清除缓存
     */
    public static void clearCache() {
        if (!sEnabledMap.isEmpty()) {
            sEnabledMap.clear();
        }
        if (!sMessageCacheMap.isEmpty()) {
            sMessageCacheMap.clear();
        }
    }

    /**
     * 信息缓存实体类
     */
    private static class MessageCacheBean {

        private List<FpData> mResults;
        private List<FpData> mHistoryResults;
        private List<String> mJsonKeys;

        public List<FpData> getResults() {
            return mResults;
        }

        public void setResults(List<FpData> mResults) {
            this.mResults = mResults;
        }

        public List<FpData> getHistoryResults() {
            return mHistoryResults;
        }

        public void setHistoryResults(List<FpData> mHistoryResults) {
            this.mHistoryResults = mHistoryResults;
        }

        public List<String> getJsonKeys() {
            return mJsonKeys;
        }

        public void setJsonKeys(List<String> mJsonKeys) {
            this.mJsonKeys = mJsonKeys;
        }

        public boolean isNotEmpty() {
            return mResults != null && !mResults.isEmpty() &&
                    mHistoryResults != null && !mHistoryResults.isEmpty() &&
                    mJsonKeys != null && !mJsonKeys.isEmpty();
        }
    }
}
