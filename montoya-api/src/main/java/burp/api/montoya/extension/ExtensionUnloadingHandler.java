/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.extension;


/**
 * Extensions can implement this interface and then call
 * {@link Extension#registerUnloadingHandler(ExtensionUnloadingHandler)}  to
 * register an extension unload handler. The handler will be notified when an
 * extension is unloaded.<br>
 * <b>Note:</b> Any extensions that start background
 * threads or open system resources (such as files or database connections)
 * should register a handler and terminate threads / close resources when the
 * extension is unloaded.
 */
public interface ExtensionUnloadingHandler
{
    /**
     * This method is invoked when the extension is unloaded.
     */
    void extensionUnloaded();
}
