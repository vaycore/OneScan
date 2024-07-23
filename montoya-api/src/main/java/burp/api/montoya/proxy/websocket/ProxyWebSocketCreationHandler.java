/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.proxy.Proxy;

/**
 * Extensions can implement this interface and then call {@link Proxy#registerWebSocketCreationHandler} to register a WebSocket handler.<br>
 * The handler will be notified of new WebSockets being created by the Proxy tool.
 */
public interface ProxyWebSocketCreationHandler
{
    /**
     * Invoked by Burp when a WebSocket is being created by the Proxy tool.<br>
     * <b>Note</b> that the client side of the connection will not be upgraded until after this method completes.
     *
     * @param webSocketCreation {@link ProxyWebSocketCreation} containing information about the proxy websocket that is being created
     */
    void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation);
}
