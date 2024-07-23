/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message;

/**
 * MIME types that are recognised by Burp.
 */
public enum MimeType
{
    NONE("none"),
    UNRECOGNIZED("unrecognized content"),
    AMBIGUOUS("ambiguous"),
    HTML("HTML"),
    PLAIN_TEXT("plain text"),
    CSS("CSS"),
    SCRIPT("script"),
    JSON("JSON"),
    RTF("RTF"),
    XML("XML"),
    YAML("YAML"),
    IMAGE_UNKNOWN("an unknown image type"),
    IMAGE_JPEG("a JPEG image"),
    IMAGE_GIF("a GIF image"),
    IMAGE_PNG("a PNG image"),
    IMAGE_BMP("a BMP image"),
    IMAGE_TIFF("a TIFF image"),
    IMAGE_SVG_XML("a SVG image"),
    SOUND("sound"),
    VIDEO("video"),
    APPLICATION_FLASH("a flash object"),
    APPLICATION_UNKNOWN("an unknown application type"),
    FONT_WOFF("a WOFF font file"),
    FONT_WOFF2("a WOFF2 font file"),
    LEGACY_SER_AMF("");

    private final String description;

    MimeType(String description)
    {
        this.description = description;
    }

    /**
     * @return MIME type description.
     */
    public String description()
    {
        return description;
    }
}
