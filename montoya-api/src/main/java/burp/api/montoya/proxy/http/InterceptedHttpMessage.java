/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.http;

import java.net.InetAddress;

/**
 * HTTP message intercepted by Burp Proxy.
 */
public interface InterceptedHttpMessage
{
    /**
     * This method retrieves a unique ID for this request/response.
     *
     * @return An identifier that is unique to a single request/response pair.
     * Extensions can use this to correlate details of requests and responses
     * and perform processing on the response message accordingly.
     */
    int messageId();

    /**
     * This method retrieves the name of the Burp Proxy listener that is
     * processing the intercepted message.
     *
     * @return The name of the Burp Proxy listener that is processing the
     * intercepted message. The format is the same as that shown in the Proxy
     * Listeners UI - for example, "127.0.0.1:8080".
     */
    String listenerInterface();

    /**
     * This method retrieves the IP address for the source of the intercepted
     * message.
     *
     * @return The IP address for the source of the intercepted message.
     */
    InetAddress sourceIpAddress();

    /**
     * This method retrieves the IP address for the destination of the
     * intercepted message.
     *
     * @return The IP address for the destination of the intercepted message.
     */
    InetAddress destinationIpAddress();
}
