/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner.audit.insertionpoint;

/**
 * This enum represents the audit insertion point type.
 */
public enum AuditInsertionPointType
{
    PARAM_URL,
    PARAM_BODY,
    PARAM_COOKIE,
    PARAM_XML,
    PARAM_XML_ATTR,
    PARAM_MULTIPART_ATTR,
    PARAM_JSON,
    PARAM_AMF,
    HEADER,
    PARAM_NAME_URL,
    PARAM_NAME_BODY,
    ENTIRE_BODY,
    URL_PATH_FILENAME,
    URL_PATH_FOLDER,
    USER_PROVIDED,
    EXTENSION_PROVIDED,
    UNKNOWN
}
