/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Provides access to the functionality of the Burp Intruder tool.
 */
public interface Intruder
{
    /**
     * Register a custom Intruder payload processor. Each registered
     * processor will be available within the Intruder UI for the user to select as the
     * action for a payload processing rule.
     *
     * @param payloadProcessor An object created by the extension that implements the
     *                         {@link PayloadProcessor} interface.
     *
     * @return The {@link Registration} for the payload processor.
     */
    Registration registerPayloadProcessor(PayloadProcessor payloadProcessor);

    /**
     * Register a provider for Intruder payloads. Each registered
     * provider will be available within the Intruder UI for the user to select as the payload
     * source for an attack. When this is selected, the provider will be asked to provide a
     * new instance of an {@link PayloadGenerator} object, which will be used to generate
     * payloads for the attack.
     *
     * @param payloadGeneratorProvider An object created by the extension that implements the
     *                                 PayloadGeneratorProvider interface.
     *
     * @return The {@link Registration} for the payload generator provider.
     */
    Registration registerPayloadGeneratorProvider(PayloadGeneratorProvider payloadGeneratorProvider);

    /**
     * Send an HTTP request to the Burp Intruder tool. The request
     * will be displayed in the user interface, and markers for attack payloads will be placed
     * into the locations specified in the provided {@link HttpRequestTemplate} object.
     *
     * @param service         An {@link HttpService} object that specifies the hostname, port and protocol
     *                        of a remote server.
     * @param requestTemplate An HTTP request template containing insertion point offsets.
     */
    void sendToIntruder(HttpService service, HttpRequestTemplate requestTemplate);

    /**
     * Send an HTTP request to the Burp Intruder tool. The request
     * will be displayed in the user interface.
     *
     * @param request The full HTTP request.
     */
    void sendToIntruder(HttpRequest request);
}
