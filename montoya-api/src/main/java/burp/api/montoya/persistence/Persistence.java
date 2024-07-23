/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.persistence;

/**
 * Provides access to the persistence functionality.
 */
public interface Persistence
{
    /**
     * Access data storage functionality in the Burp project. When Burp is started without
     * a project file, the data is stored in memory.
     *
     * @return An implementation of the {@link PersistedObject} interface
     * that stores data in either the project file or memory.
     */
    PersistedObject extensionData();

    /**
     * Access Java preference store functionality
     * in a way that survives reloads of the extension and of Burp Suite.
     *
     * @return An implementation of the {@link Preferences} interface
     * that stores data in a persistent way.
     */
    Preferences preferences();
}
