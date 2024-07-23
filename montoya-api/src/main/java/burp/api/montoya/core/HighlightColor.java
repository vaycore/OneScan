/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Colors that can be used for highlights in Burp Suite.
 */
public enum HighlightColor
{
    NONE("None"),
    RED("Red"),
    ORANGE("Orange"),
    YELLOW("Yellow"),
    GREEN("Green"),
    CYAN("Cyan"),
    BLUE("Blue"),
    PINK("Pink"),
    MAGENTA("Magenta"),
    GRAY("Gray");

    private final String displayName;

    HighlightColor(String displayName)
    {
        this.displayName = displayName;
    }

    /**
     * @return displayName of highlightColor
     */
    public String displayName()
    {
        return displayName;
    }

    /**
     * Create HighlightColor from display name string.
     *
     * @param colorName Color's display name
     *
     * @return highlight color instance
     */
    public static HighlightColor highlightColor(String colorName)
    {
        return FACTORY.highlightColor(colorName);
    }
}
