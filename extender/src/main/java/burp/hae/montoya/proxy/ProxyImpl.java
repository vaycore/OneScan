package burp.hae.montoya.proxy;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.*;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;

import java.util.List;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class ProxyImpl implements Proxy {

    private final IBurpExtenderCallbacks callbacks;

    public ProxyImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void enableIntercept() {

    }

    @Override
    public void disableIntercept() {

    }

    @Override
    public List<ProxyHttpRequestResponse> history() {
        return null;
    }

    @Override
    public List<ProxyHttpRequestResponse> history(ProxyHistoryFilter filter) {
        return null;
    }

    @Override
    public List<ProxyWebSocketMessage> webSocketHistory() {
        return null;
    }

    @Override
    public List<ProxyWebSocketMessage> webSocketHistory(ProxyWebSocketHistoryFilter filter) {
        return null;
    }

    @Override
    public Registration registerRequestHandler(ProxyRequestHandler handler) {
        return null;
    }

    @Override
    public Registration registerResponseHandler(ProxyResponseHandler handler) {
        return null;
    }

    @Override
    public Registration registerWebSocketCreationHandler(ProxyWebSocketCreationHandler handler) {
        return null;
    }
}
