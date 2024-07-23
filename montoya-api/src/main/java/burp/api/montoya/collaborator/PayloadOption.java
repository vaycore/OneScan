/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

/**
 * Options that can be specified when generating Burp Collaborator payloads.
 */
public enum PayloadOption
{
    /**
     * Generate a payload excluding the server location
     */
    WITHOUT_SERVER_LOCATION
}
