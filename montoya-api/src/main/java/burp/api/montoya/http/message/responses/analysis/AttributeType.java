/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.responses.analysis;

/**
 * Otions that Burp can use to query attributes of HTTP responses.
 */
public enum AttributeType
{
    STATUS_CODE,
    ETAG_HEADER,
    LAST_MODIFIED_HEADER,
    CONTENT_TYPE,
    CONTENT_LENGTH,
    COOKIE_NAMES,
    TAG_NAMES,
    TAG_IDS,
    DIV_IDS,
    BODY_CONTENT,
    VISIBLE_TEXT,
    WORD_COUNT,
    VISIBLE_WORD_COUNT,
    COMMENTS,
    INITIAL_CONTENT,
    CANONICAL_LINK,
    PAGE_TITLE,
    FIRST_HEADER_TAG,
    HEADER_TAGS,
    ANCHOR_LABELS,
    INPUT_SUBMIT_LABELS,
    BUTTON_SUBMIT_LABELS,
    CSS_CLASSES,
    LINE_COUNT,
    LIMITED_BODY_CONTENT,
    OUTBOUND_EDGE_COUNT,
    OUTBOUND_EDGE_TAG_NAMES,
    INPUT_IMAGE_LABELS,
    CONTENT_LOCATION,
    LOCATION,
    NON_HIDDEN_FORM_INPUT_TYPES
}
