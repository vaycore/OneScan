/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.sessions;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * An instance of this interface should be returned by {@link SessionHandlingAction#performAction(SessionHandlingActionData)}.
 */
public interface ActionResult
{
    /**
     * @return The HTTP request.
     */
    HttpRequest request();

    /**
     * @return The annotations.
     */
    Annotations annotations();

    /**
     * Create a new instance of {@code ActionResult}.<br>
     * Annotations will not be modified.
     *
     * @param request An HTTP request.
     *
     * @return A new {@code ActionResult} instance.
     */
    static ActionResult actionResult(HttpRequest request)
    {
        return FACTORY.actionResult(request);
    }

    /**
     * Create a new instance of {@code ActionResult}.
     *
     * @param request     An HTTP request.
     * @param annotations modified annotations.
     *
     * @return A new {@code ActionResult} instance.
     */
    static ActionResult actionResult(HttpRequest request, Annotations annotations)
    {
        return FACTORY.actionResult(request, annotations);
    }
}
