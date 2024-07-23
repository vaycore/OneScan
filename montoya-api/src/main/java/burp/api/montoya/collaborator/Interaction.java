/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

import java.net.InetAddress;
import java.time.ZonedDateTime;
import java.util.Optional;

/**
 * Provides details of an interaction with the Burp Collaborator
 * server.
 */
public interface Interaction
{
    /**
     * Interaction id.
     *
     * @return The interaction id.
     */
    InteractionId id();

    /**
     * Interaction Type.
     *
     * @return The type of interaction.
     */
    InteractionType type();

    /**
     * Timestamp of the interaction.
     *
     * @return The timestamp of the interaction.
     */
    ZonedDateTime timeStamp();

    /**
     * Client IP address of the interaction.
     *
     * @return The IP address of the client performing the interaction.
     */
    InetAddress clientIp();

    /**
     * Client port of the interaction.
     *
     * @return The port of the client initiating the interaction.
     */
    int clientPort();

    /**
     * DNS interaction details.
     *
     * @return Details of the DNS interaction or empty if the interaction was
     * not DNS.
     */
    Optional<DnsDetails> dnsDetails();

    /**
     * HTTP interaction details.
     *
     * @return Details of the HTTP interaction or empty if the interaction was
     * not HTTP.
     */
    Optional<HttpDetails> httpDetails();

    /**
     * SMTP interaction details.
     *
     * @return Details of the SMTP interaction or empty if the interaction was
     * not SMTP.
     */
    Optional<SmtpDetails> smtpDetails();

    /**
     * Custom data from the payload.
     *
     * @return The custom data.
     */
    Optional<String> customData();
}
