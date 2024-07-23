/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.sessions;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

/**
 * Information required for session handling.
 */
public interface SessionHandlingActionData
{
    /**
     * @return The base request that is currently being processed.
     */
    HttpRequest request();

    /**
     * If the action is invoked following execution of a macro, this method contains the result of executing the macro. Otherwise, it is an empty list. Actions can use the details
     * of the macro items to perform custom analysis of the macro to derive values of non-standard session handling tokens, etc.
     *
     * @return List of {@link HttpRequestResponse} generated during the execution of the macro.
     */
    List<HttpRequestResponse> macroRequestResponses();

    /**
     * @return The message annotation on the request.
     */
    Annotations annotations();
}
