/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

/**
 * Options that can be used to generate a new HttpRequestTemplate.
 */
public enum HttpRequestTemplateGenerationOptions
{
    /**
     * Replace base parameter value with offsets.
     */
    REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS,

    /**
     * Append offsets to base parameter value.
     */
    APPEND_OFFSETS_TO_BASE_PARAMETER_VALUE
}
