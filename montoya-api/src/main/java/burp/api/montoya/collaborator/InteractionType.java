/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

/**
 * Possible types of interaction with Burp Collaborator.
 */
public enum InteractionType
{
    /**
     * Domain Name System
     */
    DNS,
    /**
     * Hypertext Transfer Protocol
     */
    HTTP,
    /**
     * Simple Mail Transfer Protocol
     */
    SMTP
}
