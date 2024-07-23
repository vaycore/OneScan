/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.handler;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * An instance of this interface should be returned by {@link HttpHandler#handleHttpRequestToBeSent} if a custom {@link HttpHandler} has been registered with Burp.
 */
public interface RequestToBeSentAction
{
    /**
     * @return the action.
     */
    default RequestAction action()
    {
        return RequestAction.CONTINUE;
    }

    /**
     * @return The HTTP request.
     */
    HttpRequest request();

    /**
     * @return The annotations.
     */
    Annotations annotations();

    /**
     * Create a new instance of {@code RequestResult}. Annotations will not be modified.
     *
     * @param request An HTTP request.
     *
     * @return A new {@code RequestHandlerResult} instance.
     */
    static RequestToBeSentAction continueWith(HttpRequest request)
    {
        return FACTORY.requestResult(request);
    }

    /**
     * Create a new instance of {@code RequestResult}.
     *
     * @param request     An HTTP request.
     * @param annotations modified annotations.
     *
     * @return A new {@code RequestHandlerResult} instance.
     */
    static RequestToBeSentAction continueWith(HttpRequest request, Annotations annotations)
    {
        return FACTORY.requestResult(request, annotations);
    }
}
