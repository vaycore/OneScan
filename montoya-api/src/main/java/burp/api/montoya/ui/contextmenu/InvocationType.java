/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

/**
 * An enum containing different types of context menu invocations.
 */
public enum InvocationType
{
    MESSAGE_EDITOR_REQUEST,
    MESSAGE_EDITOR_RESPONSE,
    MESSAGE_VIEWER_REQUEST,
    MESSAGE_VIEWER_RESPONSE,
    SITE_MAP_TREE,
    SITE_MAP_TABLE,
    PROXY_HISTORY,
    SCANNER_RESULTS,
    INTRUDER_PAYLOAD_POSITIONS,
    INTRUDER_ATTACK_RESULTS,
    SEARCH_RESULTS;

    /**
     * @return A helper method to ask if this type contains HTTP messages.
     */
    public boolean containsHttpMessage()
    {
        switch (this)
        {
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_EDITOR_RESPONSE:
            case MESSAGE_VIEWER_REQUEST:
            case MESSAGE_VIEWER_RESPONSE:
            case INTRUDER_PAYLOAD_POSITIONS:
                return true;
        }

        return false;
    }

    /**
     * @return A helper method to ask if this type contains HTTP request/responses.
     */
    public boolean containsHttpRequestResponses()
    {
        switch (this)
        {
            case SITE_MAP_TREE:
            case SITE_MAP_TABLE:
            case PROXY_HISTORY:
            case INTRUDER_ATTACK_RESULTS:
            case SEARCH_RESULTS:
                return true;
        }

        return false;
    }

    /**
     * @return A helper method to ask if this type contains any scan issues.
     */
    public boolean containsScanIssues()
    {
        return this == SCANNER_RESULTS;
    }
}
