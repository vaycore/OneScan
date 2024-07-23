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
 * {@link Proxy#registerResponseHandler(ProxyResponseHandler)} to register a
 * Proxy response handler. The handler will be notified of responses being
 * processed by the Proxy tool. Extensions can perform custom analysis or
 * modification of these responses, and control in-UI message interception.
 */
public interface ProxyResponseHandler
{
    /**
     * This method is invoked when an HTTP response is received in the Proxy.
     *
     * @param interceptedResponse An {@link InterceptedResponse} object
     *                            that extensions can use to query and update details of the response, and
     *                            control whether the response should be intercepted and displayed to the
     *                            user for manual review or modification.
     *
     * @return The {@link ProxyResponseReceivedAction} containing the required action, HTTP response and annotations to be passed through.
     */
    ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse);

    /**
     * This method is invoked when an HTTP response has been processed by the
     * Proxy before it is returned to the client.
     *
     * @param interceptedResponse An {@link InterceptedResponse} object
     *                            that extensions can use to query and update details of the response.
     *
     * @return The {@link ProxyResponseToBeSentAction} containing the required action, HTTP response and annotations to be passed through.
     */
    ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse);
}
