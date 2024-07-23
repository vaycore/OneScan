/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.handler;

import java.time.Duration;
import java.time.ZonedDateTime;

/**
 * Timing data
 */
public interface TimingData
{
    /**
     * The time between when Burp sent the request and the start of the response being received.
     *
     * @return the duration or null if no response returned.
     */
    Duration timeBetweenRequestSentAndStartOfResponse();

    /**
     * The time between when Burp sent the request and the end of the response being received.
     *
     * @return the duration or null if no response returned or the response never completes.
     */
    Duration timeBetweenRequestSentAndEndOfResponse();

    /**
     * The time that Burp issued the request.
     *
     * @return the time that Burp issued the request.
     */
    ZonedDateTime timeRequestSent();
}