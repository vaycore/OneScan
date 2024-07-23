/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.persistence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * List that has been persisted in the project.
 * The methods of this list operate on the underlying persisted data.
 */
public interface PersistedList<T> extends List<T>
{
    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link Boolean}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<Boolean> persistedBooleanList()
    {
        return FACTORY.persistedBooleanList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link Short}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<Short> persistedShortList()
    {
        return FACTORY.persistedShortList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link Integer}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<Integer> persistedIntegerList()
    {
        return FACTORY.persistedIntegerList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link Long}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<Long> persistedLongList()
    {
        return FACTORY.persistedLongList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link String}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<String> persistedStringList()
    {
        return FACTORY.persistedStringList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link ByteArray}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<ByteArray> persistedByteArrayList()
    {
        return FACTORY.persistedByteArrayList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link HttpRequest}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<HttpRequest> persistedHttpRequestList()
    {
        return FACTORY.persistedHttpRequestList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link HttpResponse}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<HttpResponse> persistedHttpResponseList()
    {
        return FACTORY.persistedHttpResponseList();
    }

    /**
     * Create a new instance of {@link PersistedList} that contains instances of {@link HttpRequestResponse}.
     *
     * @return A new {@link PersistedList} instance.
     */
    static PersistedList<HttpRequestResponse> persistedHttpRequestResponseList()
    {
        return FACTORY.persistedHttpRequestResponseList();
    }
}
