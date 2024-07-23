/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy;

import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;

import java.util.List;

/**
 * Provides access to the functionality of the Proxy tool.
 */
public interface Proxy
{
    /**
     * This method enables the master interception for Burp Proxy.
     */
    void enableIntercept();

    /**
     * This method disables the master interception for Burp Proxy.
     */
    void disableIntercept();

    /**
     * This method returns details of all items in the Proxy HTTP history.
     *
     * @return The list of all the {@link ProxyHttpRequestResponse} items in the
     * Proxy HTTP history.
     */
    List<ProxyHttpRequestResponse> history();

    /**
     * This method returns details of items in the Proxy HTTP history based on
     * the filter.
     *
     * @param filter An instance of {@link ProxyHistoryFilter} that can be used
     *               to filter the items in the Proxy history.
     *
     * @return The list of {@link ProxyHttpRequestResponse} items in the Proxy
     * HTTP history that matched the filter.
     */
    List<ProxyHttpRequestResponse> history(ProxyHistoryFilter filter);

    /**
     * This method returns details of all items in the Proxy WebSockets history.
     *
     * @return The list of all the {@link ProxyWebSocketMessage} items in the
     * Proxy WebSockets history.
     */
    List<ProxyWebSocketMessage> webSocketHistory();

    /**
     * This method returns details of items in the Proxy WebSockets history based
     * on the filter.
     *
     * @param filter An instance of {@link ProxyWebSocketHistoryFilter} that can be used
     *               to filter the items in the Proxy WebSockets history.
     *
     * @return The list of {@link ProxyWebSocketMessage} items in the Proxy WebSockets
     * history that matched the filter.
     */
    List<ProxyWebSocketMessage> webSocketHistory(ProxyWebSocketHistoryFilter filter);

    /**
     * Register a handler which will be notified of
     * requests being processed by the Proxy tool. Extensions can perform
     * custom analysis or modification of these messages, and control in-UI
     * message interception.
     *
     * @param handler An object created by the extension that implements the
     *                {@link ProxyRequestHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerRequestHandler(ProxyRequestHandler handler);

    /**
     * Register a handler which will be notified of
     * responses being processed by the Proxy tool. Extensions can perform
     * custom analysis or modification of these messages, and control in-UI
     * message interception.
     *
     * @param handler An object created by the extension that implements the
     *                {@link ProxyResponseHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerResponseHandler(ProxyResponseHandler handler);

    /**
     * Register a handler which will be invoked whenever a WebSocket is being created by the Proxy tool.
     *
     * @param handler An object created by the extension that implements {@link ProxyWebSocketCreationHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerWebSocketCreationHandler(ProxyWebSocketCreationHandler handler);
}
