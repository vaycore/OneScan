/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.extension;

import burp.api.montoya.core.Registration;

/**
 * Provides access to functionality related to your Extension.
 */
public interface Extension
{
    /**
     * Set the display name for the current extension.<br/>
     * This will be displayed within the user interface for the Extensions tool and
     * will be used to identify persisted data.
     *
     * @param extensionName the name of the extension
     */
    void setName(String extensionName);

    /**
     * Absolute path name of the file from which the current extension was loaded.
     *
     * @return The absolute path name of the file from which the current
     * extension was loaded.
     */
    String filename();

    /**
     * Determines whether the current extension was loaded as a BApp.
     *
     * @return Returns {@code true} if the current extension was loaded as
     * a BApp.
     */
    boolean isBapp();

    /**
     * Unload the extension from Burp Suite.
     */
    void unload();

    /**
     * Register a handler which will be notified of changes to the extension's state.<br>
     * <b>Note:</b> Any extensions that start
     * background threads or open system resources (such as files or database
     * connections) should register a listener and terminate threads / close
     * resources when the extension is unloaded.
     *
     * @param handler An object created by the extension that implements the
     *                {@link ExtensionUnloadingHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerUnloadingHandler(ExtensionUnloadingHandler handler);
}
