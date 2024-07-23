/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.http;

import burp.api.montoya.proxy.Proxy;

/**
 * Extensions can implement this interface and then call
 * {@link Proxy#registerRequestHandler(ProxyRequestHandler)} to register a
 * Proxy request handler. The handler will be notified of requests being
 * processed by the Proxy tool. Extensions can perform custom analysis or
 * modification of these messages, and control in-UI message interception.
 */
public interface ProxyRequestHandler
{
    /**
     * This method is invoked before an HTTP request is received by the Proxy.<br>
     * Can modify the request.<br>
     * Can modify the annotations.<br>
     * Can control whether the request should be intercepted and displayed to the user for manual review or modification.<br>
     * Can drop the request.<br>
     *
     * @param interceptedRequest An {@link InterceptedRequest} object that extensions can use to query and update details of the request.
     *
     * @return The {@link ProxyRequestReceivedAction} containing the required action, annotations and HTTP request to be passed through the proxy.
     */
    ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest);

    /**
     * This method is invoked after an HTTP request has been processed by the Proxy before it is sent.<br>
     * Can modify the request.<br>
     * Can modify the annotations.<br>
     * Can control whether the request is sent or dropped.<br>
     *
     * @param interceptedRequest An {@link InterceptedRequest} object that extensions can use to query and update details of the intercepted request.
     *
     * @return The {@link ProxyRequestToBeSentAction} containing the required action, annotations and HTTP request to be sent from the proxy.
     */
    ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest);
}
