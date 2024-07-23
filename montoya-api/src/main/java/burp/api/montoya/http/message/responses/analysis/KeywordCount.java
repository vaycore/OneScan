/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.responses.analysis;

/**
 * Stores the number of types a given keyword appeared in a response.
 */
public interface KeywordCount
{
    /**
     * @return The keyword.
     */
    String keyword();

    /**
     * @return The number of times the keyword appeared in a response.
     */
    int count();
}
