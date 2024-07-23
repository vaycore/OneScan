/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

import burp.api.montoya.http.HttpService;

import java.util.Optional;

/**
 * Intruder attack configuration.
 */
public interface AttackConfiguration
{
    /**
     * {@link HttpService} for the attack.
     *
     * @return An {@link Optional} of {@link HttpService} instance derived from this attack configuration or {@link Optional#empty} if the target template contains payload markers.
     */
    Optional<HttpService> httpService();

    /**
     * HTTP request template and insertion point offsets in a
     * form of an {@link HttpRequestTemplate} instance.
     *
     * @return An instance of {@link HttpRequestTemplate}.
     */
    HttpRequestTemplate requestTemplate();
}
