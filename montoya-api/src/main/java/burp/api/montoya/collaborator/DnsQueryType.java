/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

/**
 * Domain Name System (DNS) query types.
 */
public enum DnsQueryType
{
    /**
     * Address Record
     */
    A,
    /**
     * IPv6 address record
     */
    AAAA,
    /**
     * All cached records
     */
    ALL,
    /**
     * Certification Authority Authorization
     */
    CAA,
    /**
     * Canonical name record
     */
    CNAME,
    /**
     * DNS Key record
     */
    DNSKEY,
    /**
     * Delegation signer
     */
    DS,
    /**
     * Host Information
     */
    HINFO,
    /**
     * HTTPS Binding
     */
    HTTPS,
    /**
     * Mail exchange record
     */
    MX,
    /**
     * Naming Authority Pointer
     */
    NAPTR,
    /**
     * Name Server Record
     */
    NS,
    /**
     * PTR Resource Record
     */
    PTR,
    /**
     * Start of authority record
     */
    SOA,
    /**
     * Service locator
     */
    SRV,
    /**
     * Text record
     */
    TXT,
    /**
     * Unknown / Not Mapped / Obsolete
     */
    UNKNOWN

}
