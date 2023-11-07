package burp.vaycore.hae;

import burp.*;

import java.awt.*;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * Created by vaycore on 2022-09-08.
 */
public class BurpCallbacksAdapter implements IBurpExtenderCallbacks {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private String extensionName;
    private IHttpListener httpListener;
    private BurpUiComponentCallback mBurpUiComponentCallback;

    public BurpCallbacksAdapter(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public String getExtensionName() {
        return extensionName;
    }

    public IHttpListener getHttpListener() {
        return httpListener;
    }

    @Override
    public void setExtensionName(String s) {
        this.extensionName = s;
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    @Override
    public OutputStream getStdout() {
        return callbacks.getStdout();
    }

    @Override
    public OutputStream getStderr() {
        return callbacks.getStderr();
    }

    @Override
    public void printOutput(String s) {

    }

    @Override
    public void printError(String s) {

    }

    @Override
    public void registerExtensionStateListener(IExtensionStateListener iExtensionStateListener) {

    }

    @Override
    public List<IExtensionStateListener> getExtensionStateListeners() {
        return null;
    }

    @Override
    public void removeExtensionStateListener(IExtensionStateListener iExtensionStateListener) {

    }

    @Override
    public void registerHttpListener(IHttpListener iHttpListener) {
        this.httpListener = iHttpListener;
    }

    @Override
    public List<IHttpListener> getHttpListeners() {
        return null;
    }

    @Override
    public void removeHttpListener(IHttpListener iHttpListener) {

    }

    @Override
    public void registerProxyListener(IProxyListener iProxyListener) {

    }

    @Override
    public List<IProxyListener> getProxyListeners() {
        return null;
    }

    @Override
    public void removeProxyListener(IProxyListener iProxyListener) {

    }

    @Override
    public void registerScannerListener(IScannerListener iScannerListener) {

    }

    @Override
    public List<IScannerListener> getScannerListeners() {
        return null;
    }

    @Override
    public void removeScannerListener(IScannerListener iScannerListener) {

    }

    @Override
    public void registerScopeChangeListener(IScopeChangeListener iScopeChangeListener) {

    }

    @Override
    public List<IScopeChangeListener> getScopeChangeListeners() {
        return null;
    }

    @Override
    public void removeScopeChangeListener(IScopeChangeListener iScopeChangeListener) {

    }

    @Override
    public void registerContextMenuFactory(IContextMenuFactory iContextMenuFactory) {

    }

    @Override
    public List<IContextMenuFactory> getContextMenuFactories() {
        return null;
    }

    @Override
    public void removeContextMenuFactory(IContextMenuFactory iContextMenuFactory) {

    }

    @Override
    public void registerMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {

    }

    @Override
    public List<IMessageEditorTabFactory> getMessageEditorTabFactories() {
        return null;
    }

    @Override
    public void removeMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {

    }

    @Override
    public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {

    }

    @Override
    public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() {
        return null;
    }

    @Override
    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {

    }

    @Override
    public void registerScannerCheck(IScannerCheck iScannerCheck) {

    }

    @Override
    public List<IScannerCheck> getScannerChecks() {
        return null;
    }

    @Override
    public void removeScannerCheck(IScannerCheck iScannerCheck) {

    }

    @Override
    public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {

    }

    @Override
    public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() {
        return null;
    }

    @Override
    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {

    }

    @Override
    public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {

    }

    @Override
    public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() {
        return null;
    }

    @Override
    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {

    }

    @Override
    public void registerSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {

    }

    @Override
    public List<ISessionHandlingAction> getSessionHandlingActions() {
        return null;
    }

    @Override
    public void removeSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {

    }

    @Override
    public void unloadExtension() {

    }

    @Override
    public void addSuiteTab(ITab iTab) {

    }

    @Override
    public void removeSuiteTab(ITab iTab) {

    }

    @Override
    public void customizeUiComponent(Component component) {
        if (this.mBurpUiComponentCallback != null) {
            this.mBurpUiComponentCallback.onUiComponentSetupEvent(component);
        }
    }

    /**
     * 设置 UI 组件设置监听器
     *
     * @param callback 监听器接口实例
     */
    public void setBurpUiComponentCallback(BurpUiComponentCallback callback) {
        this.mBurpUiComponentCallback = callback;
    }

    @Override
    public IMessageEditor createMessageEditor(IMessageEditorController iMessageEditorController, boolean b) {
        return callbacks.createMessageEditor(iMessageEditorController, b);
    }

    @Override
    public String[] getCommandLineArguments() {
        return new String[0];
    }

    @Override
    public void saveExtensionSetting(String s, String s1) {

    }

    @Override
    public String loadExtensionSetting(String s) {
        return null;
    }

    @Override
    public ITextEditor createTextEditor() {
        return null;
    }

    @Override
    public void sendToRepeater(String s, int i, boolean b, byte[] bytes, String s1) {

    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes) {

    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes, List<int[]> list) {

    }

    @Override
    public void sendToComparer(byte[] bytes) {

    }

    @Override
    public void sendToSpider(URL url) {

    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes) {
        return null;
    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes, List<int[]> list) {
        return null;
    }

    @Override
    public void doPassiveScan(String s, int i, boolean b, byte[] bytes, byte[] bytes1) {

    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService iHttpService, byte[] bytes) {
        return null;
    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService iHttpService, byte[] bytes, boolean b) {
        return null;
    }

    @Override
    public byte[] makeHttpRequest(String s, int i, boolean b, byte[] bytes) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttpRequest(String s, int i, boolean b, byte[] bytes, boolean b1) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttp2Request(IHttpService iHttpService, List<IHttpHeader> list, byte[] bytes) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttp2Request(IHttpService iHttpService, List<IHttpHeader> list, byte[] bytes, boolean b) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttp2Request(IHttpService iHttpService, List<IHttpHeader> list, byte[] bytes, boolean b, String s) {
        return new byte[0];
    }

    @Override
    public boolean isInScope(URL url) {
        return false;
    }

    @Override
    public void includeInScope(URL url) {

    }

    @Override
    public void excludeFromScope(URL url) {

    }

    @Override
    public void issueAlert(String s) {

    }

    @Override
    public IHttpRequestResponse[] getProxyHistory() {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IHttpRequestResponse[] getSiteMap(String s) {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IScanIssue[] getScanIssues(String s) {
        return new IScanIssue[0];
    }

    @Override
    public void generateScanReport(String s, IScanIssue[] iScanIssues, File file) {

    }

    @Override
    public List<ICookie> getCookieJarContents() {
        return null;
    }

    @Override
    public void updateCookieJar(ICookie iCookie) {

    }

    @Override
    public void addToSiteMap(IHttpRequestResponse iHttpRequestResponse) {

    }

    @Override
    public void restoreState(File file) {

    }

    @Override
    public void saveState(File file) {

    }

    @Override
    public Map<String, String> saveConfig() {
        return null;
    }

    @Override
    public void loadConfig(Map<String, String> map) {

    }

    @Override
    public String saveConfigAsJson(String... strings) {
        return null;
    }

    @Override
    public void loadConfigFromJson(String s) {

    }

    @Override
    public void setProxyInterceptionEnabled(boolean b) {

    }

    @Override
    public String[] getBurpVersion() {
        return new String[0];
    }

    @Override
    public String getExtensionFilename() {
        return null;
    }

    @Override
    public boolean isExtensionBapp() {
        return false;
    }

    @Override
    public void exitSuite(boolean b) {

    }

    @Override
    public ITempFile saveToTempFile(byte[] bytes) {
        return null;
    }

    @Override
    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse iHttpRequestResponse) {
        return callbacks.saveBuffersToTempFiles(iHttpRequestResponse);
    }

    @Override
    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse iHttpRequestResponse, List<int[]> list, List<int[]> list1) {
        return null;
    }

    @Override
    public String getToolName(int i) {
        return null;
    }

    @Override
    public void addScanIssue(IScanIssue iScanIssue) {

    }

    @Override
    public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() {
        return null;
    }

    @Override
    public String[][] getParameters(byte[] bytes) {
        return new String[0][];
    }

    @Override
    public String[] getHeaders(byte[] bytes) {
        return new String[0];
    }

    @Override
    public void registerMenuItem(String s, IMenuItemHandler iMenuItemHandler) {

    }

    /**
     * UI 组件设置回调
     */
    public interface BurpUiComponentCallback {

        /**
         * 组件设置事件
         *
         * @param component 组件实例
         */
        void onUiComponentSetupEvent(Component component);
    }
}
