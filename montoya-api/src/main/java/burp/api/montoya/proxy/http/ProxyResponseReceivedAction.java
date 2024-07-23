/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.http;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.MessageReceivedAction;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Extensions can implement this interface when returning a result from
 * {@link ProxyResponseHandler#handleResponseReceived(InterceptedResponse)}.
 */
public interface ProxyResponseReceivedAction
{
    /**
     * This method retrieves the current initial intercept action.
     *
     * @return The {@link MessageReceivedAction}.
     */
    MessageReceivedAction action();

    /**
     * This method retrieves the current HTTP response to forward after any
     * modifications by the extension.
     *
     * @return The {@link HttpResponse} to forward after any modifications by
     * the extension.
     */
    HttpResponse response();

    /**
     * This method retrieves the annotations for the current response after any
     * modifications by the extension.
     *
     * @return The {@link Annotations} for the intercepted HTTP response.
     */
    Annotations annotations();

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * follow the current interception rules to determine the appropriate
     * action to take for the response.<br>
     * Annotations are not modified.
     *
     * @param response The {@link HttpResponse} received after any
     *                 modifications by the extension.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to follow the current interception rules to determine the
     * appropriate action to take for the response.
     */
    static ProxyResponseReceivedAction continueWith(HttpResponse response)
    {
        return FACTORY.responseInitialInterceptResultFollowUserRules(response);
    }

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * follow the current interception rules to determine the appropriate
     * action to take for the response.
     *
     * @param response    The {@link HttpResponse} received after any
     *                    modifications by the extension.
     * @param annotations The {@link Annotations} for the intercepted
     *                    HTTP response.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to follow the current interception rules to determine the
     * appropriate action to take for the response.
     */
    static ProxyResponseReceivedAction continueWith(HttpResponse response, Annotations annotations)
    {
        return FACTORY.responseInitialInterceptResultFollowUserRules(response, annotations);
    }

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * present the response to the user for manual review or modification.<br>
     * Annotations are not modified.
     *
     * @param response The {@link HttpResponse} received after any
     *                 modifications by the extension.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to present the response to the user for manual review or
     * modification.
     */
    static ProxyResponseReceivedAction intercept(HttpResponse response)
    {
        return FACTORY.responseInitialInterceptResultIntercept(response);
    }

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * present the response to the user for manual review or modification.
     *
     * @param response    The {@link HttpResponse} received after any
     *                    modifications by the extension.
     * @param annotations The {@link Annotations} for the intercepted
     *                    HTTP response.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to present the response to the user for manual review or
     * modification.
     */
    static ProxyResponseReceivedAction intercept(HttpResponse response, Annotations annotations)
    {
        return FACTORY.responseInitialInterceptResultIntercept(response, annotations);
    }

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * forward the response without presenting it to the user.<br>
     * Annotations are not modified.
     *
     * @param response The {@link HttpResponse} received after any
     *                 modifications by the extension.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to forward the response without presenting it to the user.
     */
    static ProxyResponseReceivedAction doNotIntercept(HttpResponse response)
    {
        return FACTORY.responseInitialInterceptResultDoNotIntercept(response);
    }

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * forward the response without presenting it to the user.
     *
     * @param response    The {@link HttpResponse} received after any
     *                    modifications by the extension.
     * @param annotations The {@link Annotations} for the intercepted
     *                    HTTP response.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to forward the response without presenting it to the user.
     */
    static ProxyResponseReceivedAction doNotIntercept(HttpResponse response, Annotations annotations)
    {
        return FACTORY.responseInitialInterceptResultDoNotIntercept(response, annotations);
    }

    /**
     * This method can be used to create an action that causes Burp Proxy to
     * drop the response.
     *
     * @return The {@link ProxyResponseReceivedAction} that causes Burp
     * Proxy to drop the response.
     */
    static ProxyResponseReceivedAction drop()
    {
        return FACTORY.responseInitialInterceptResultDrop();
    }

    /**
     * This method can be used to create a default implementation of a {@link ProxyResponseReceivedAction}
     * for an HTTP response.
     *
     * @param response    The {@link HttpResponse} received after any modifications by the extension.
     * @param annotations The {@link Annotations} for the intercepted HTTP response. {@code null} value will leave the annotations unmodified.
     * @param action      The {@link MessageReceivedAction} for the HTTP response.
     *
     * @return The {@link ProxyResponseReceivedAction} including the HTTP response, annotations and intercept action.
     */
    static ProxyResponseReceivedAction proxyResponseReceivedAction(HttpResponse response, Annotations annotations, MessageReceivedAction action)
    {
        return FACTORY.proxyResponseReceivedAction(response, annotations, action);
    }
}
