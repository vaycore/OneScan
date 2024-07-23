/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.handler;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.responses.HttpResponse;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * An instance of this interface should be returned by {@link HttpHandler#handleHttpResponseReceived} if a custom {@link HttpHandler} has been registered with Burp.
 */
public interface ResponseReceivedAction
{
    /**
     * @return the action.
     */
    default ResponseAction action()
    {
        return ResponseAction.CONTINUE;
    }

    /**
     * @return The HTTP response.
     */
    HttpResponse response();

    /**
     * @return The annotations.
     */
    Annotations annotations();

    /**
     * Create a new instance of {@code ResponseResult}. Annotations will not be modified.
     *
     * @param response An HTTP response.
     *
     * @return A new {@code ResponseResult} instance.
     */
    static ResponseReceivedAction continueWith(HttpResponse response)
    {
        return FACTORY.responseResult(response);
    }

    /**
     * Create a new instance of {@code ResponseResult}.
     *
     * @param response    An HTTP response.
     * @param annotations modified annotations.
     *
     * @return A new {@code ResponseResult} instance.
     */
    static ResponseReceivedAction continueWith(HttpResponse response, Annotations annotations)
    {
        return FACTORY.responseResult(response, annotations);
    }
}
