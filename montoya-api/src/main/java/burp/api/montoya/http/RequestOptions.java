package burp.api.montoya.http;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Interface used to specify options for making HTTP requests.
 */
public interface RequestOptions
{
    /**
     * Specify HTTP mode to be used when request sent.
     *
     * @param httpMode An {@link HttpMode} enum value which indicates how a request should be sent.
     *
     * @return request options
     */
    RequestOptions withHttpMode(HttpMode httpMode);

    /**
     * Specify connectionId when sending request over specific connection.
     *
     * @param connectionId The connection identifier to use.
     *
     * @return request options
     */
    RequestOptions withConnectionId(String connectionId);

    /**
     * Enforce upstream TLS verification when request sent.
     *
     * @return request options
     */
    RequestOptions withUpstreamTLSVerification();

    /**
     * Use to obtain a new RequestOptions instance
     *
     * @return request options
     */
    static RequestOptions requestOptions()
    {
        return FACTORY.requestOptions();
    }
}
