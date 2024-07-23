/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

import burp.api.montoya.core.ByteArray;

/**
 * Provides information about a DNS interaction detected by Burp
 * Collaborator.
 */
public interface DnsDetails
{
    /**
     * DNS query type.
     *
     * @return The type of DNS query performed by the interaction.
     */
    DnsQueryType queryType();

    /**
     * Raw DNS query.
     *
     * @return The raw DNS query sent to the Collaborator server.
     */
    ByteArray query();
}
