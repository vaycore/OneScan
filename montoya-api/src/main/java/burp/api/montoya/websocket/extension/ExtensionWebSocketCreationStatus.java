/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket.extension;

/**
 * Status of a WebSocket creation attempt
 */
public enum ExtensionWebSocketCreationStatus
{
    /**
     * WebSocket creation was successful.
     */
    SUCCESS,

    /**
     * Specified host was invalid.
     */
    INVALID_HOST,

    /**
     * Unable to resolve address for specified host.
     */
    UNKNOWN_HOST,

    /**
     * Specified port was invalid.
     */
    INVALID_PORT,

    /**
     * Unable to connect to specified host.
     */
    CONNECTION_FAILED,

    /**
     * Specified upgrade request was invalid.
     */
    INVALID_REQUEST,

    /**
     * Server returned a non-upgrade response.
     */
    NON_UPGRADE_RESPONSE,

    /**
     * Specified endpoint is configured for streaming responses.
     */
    STREAMING_RESPONSE
}
