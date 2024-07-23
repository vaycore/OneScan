/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.handler;

import burp.api.montoya.http.Http;

/**
 * Extensions can implement this interface and then call {@link Http#registerHttpHandler} to register an HTTP handler. The handler
 * will be notified of requests and responses made and received by any Burp tool. Extensions can perform custom analysis or modification
 * of these messages by registering an HTTP handler.
 */
public interface HttpHandler
{
    /**
     * Invoked by Burp when an HTTP request is about to be sent.
     *
     * @param requestToBeSent information about the HTTP request that is going to be sent.
     *
     * @return An instance of {@link RequestToBeSentAction}.
     */
    RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent);

    /**
     * Invoked by Burp when an HTTP response has been received.
     *
     * @param responseReceived information about HTTP response that was received.
     *
     * @return An instance of {@link ResponseReceivedAction}.
     */
    ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived);
}
