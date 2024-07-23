/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

/**
 * Product version.<br>
 * e.g. Burp Suite Professional 2022.8.1-9320
 */
public interface Version
{
    /**
     * The product name (e.g. Burp Suite Professional).
     *
     * @return The product name.
     */
    String name();

    /**
     * The major version (e.g. 2022.8).
     *
     * @return The major version.
     * @deprecated use {@link #toString()} or {@link #buildNumber()} instead.
     */
    @Deprecated()
    String major();

    /**
     * The minor version (e.g. 1).
     *
     * @return The minor version.
     * @deprecated use {@link #toString()} or {@link #buildNumber()} instead.
     */
    @Deprecated()
    String minor();

    /**
     * The build number (e.g. 9320).
     *
     * @return The build number.
     * @deprecated use {@link #toString()} or {@link #buildNumber()} instead.
     */
    @Deprecated()
    String build();

    /**
     * Build number for Burp Suite. You can use this to determine compatibility with different versions of Burp Suite. Do not parse this information, because the format of the number may change.
     *
     * @return The build number.
     */
    long buildNumber();

    /**
     * The edition of Burp Suite
     *
     * @return The edition of Burp Suite
     */
    BurpSuiteEdition edition();

    /**
     * The human-readable version string. Do not parse this information, because the format may change. See also: {@link #buildNumber()}.
     *
     * @return The human-readable version string.
     */
    @Override
    String toString();
}
