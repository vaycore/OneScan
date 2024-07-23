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

import java.util.Set;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * [Professional only] Enables data to be stored and accessed from the Burp project.
 * Supports HTTP requests, HTTP responses, byte arrays, primitives, lists of all these, and object hierarchies.
 */
public interface PersistedObject
{
    /**
     * {@link PersistedObject} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value to which the specified key is mapped, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedObject getChildObject(String key);

    /**
     * Associates the specified {@link PersistedObject} with the specified key in this map.
     * If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key         The key with which the specified child object is to be associated.
     * @param childObject The {@link PersistedObject} to be associated with the specified key.
     */
    void setChildObject(String key, PersistedObject childObject);

    /**
     * Removes the mapping of the specified key to the {@link PersistedObject}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteChildObject(String key);

    /**
     * Retrieve all keys currently mapped for {@link PersistedObject} objects.
     *
     * @return Set of keys.
     */
    Set<String> childObjectKeys();

    /**
     * {@link String} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    String getString(String key);

    /**
     * Associates the specified {@link String} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setString(String key, String value);

    /**
     * Removes the mapping of the specified key to the {@link String}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteString(String key);

    /**
     * Retrieve all keys currently mapped for {@link String} values.
     *
     * @return Set of keys.
     */
    Set<String> stringKeys();

    /**
     * {@link Boolean} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Boolean getBoolean(String key);

    /**
     * Associates the specified {@code boolean} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
     */
    void setBoolean(String key, boolean value);

    /**
     * Removes the mapping of the specified key to the {@link Boolean}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteBoolean(String key);

    /**
     * Retrieve all keys currently mapped for {@link Boolean} values.
     *
     * @return Set of keys.
     */
    Set<String> booleanKeys();

    /**
     * {@link Byte} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Byte getByte(String key);

    /**
     * Associates the specified {@code byte} with the specified key in this map
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
     */
    void setByte(String key, byte value);

    /**
     * Removes the mapping of the specified key to the {@link Byte}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteByte(String key);

    /**
     * Retrieve all keys currently mapped for {@link Byte} values.
     *
     * @return Set of keys.
     */
    Set<String> byteKeys();

    /**
     * {@link Short} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Short getShort(String key);

    /**
     * Associates the specified short with the specified key in this map
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value currently mapped to the specified key is removed.
     */
    void setShort(String key, short value);

    /**
     * Removes the mapping from the specified key to the {@link Short}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteShort(String key);

    /**
     * Retrieve all keys currently mapped for {@link Short} values.
     *
     * @return Set of keys.
     */
    Set<String> shortKeys();

    /**
     * {@link Integer} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Integer getInteger(String key);

    /**
     * Associates the specified {@code int}  with the specified key in this map
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
     */
    void setInteger(String key, int value);

    /**
     * Removes the mapping from the specified key to the {@link Integer}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteInteger(String key);

    /**
     * Retrieve all keys currently mapped for {@link Integer} values.
     *
     * @return Set of keys.
     */
    Set<String> integerKeys();

    /**
     * {@link Long} associated with the specified key,
     * or {@code null}} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Long getLong(String key);

    /**
     * Associates the specified {@code long} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
     */
    void setLong(String key, long value);

    /**
     * Removes the mapping from the specified key to the {@link Long}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteLong(String key);

    /**
     * Retrieve all keys currently mapped for {@link Long} values.
     *
     * @return Set of keys.
     */
    Set<String> longKeys();

    /**
     * {@link ByteArray} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    ByteArray getByteArray(String key);

    /**
     * Associates the specified {@code ByteArray} with the specified key in this map.
     * If the map previously contained a mapping for the key, the old value is replaced
     * by the specified value.
     *
     * @param key  The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setByteArray(String key, ByteArray value);

    /**
     * Removes the mapping of the specified key to the {@link ByteArray}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteByteArray(String key);

    /**
     * Retrieve all keys currently mapped for {@link ByteArray} values.
     *
     * @return Set of keys.
     */
    Set<String> byteArrayKeys();

    /**
     * {@link HttpRequest} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    HttpRequest getHttpRequest(String key);

    /**
     * Associates the specified {@link HttpRequest} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setHttpRequest(String key, HttpRequest value);

    /**
     * Removes the mapping of the specified key to the {@link HttpRequest}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteHttpRequest(String key);

    /**
     * Retrieve all keys currently mapped for {@link HttpRequest} values.
     *
     * @return Set of keys.
     */
    Set<String> httpRequestKeys();

    /**
     * {@link PersistedList} of {@link HttpRequest} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<HttpRequest> getHttpRequestList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link HttpRequest} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              The methods of this list operate on the underlying persisted data.
     */
    void setHttpRequestList(String key, PersistedList<HttpRequest> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link HttpRequest}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteHttpRequestList(String key);

    /**
     * Retrieve all keys currently mapped for {@link HttpRequest} Lists.
     *
     * @return Set of keys.
     */
    Set<String> httpRequestListKeys();

    /**
     * {@link HttpResponse} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    HttpResponse getHttpResponse(String key);

    /**
     * Associates the specified {@link HttpResponse} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setHttpResponse(String key, HttpResponse value);

    /**
     * Removes the mapping of the specified key to the {@link HttpResponse}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteHttpResponse(String key);

    /**
     * Retrieve all keys currently mapped for {@link HttpResponse} values.
     *
     * @return Set of keys.
     */
    Set<String> httpResponseKeys();

    /**
     * {@link PersistedList} of {@link HttpResponse} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<HttpResponse> getHttpResponseList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link HttpResponse} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              The methods of this list operate on the underlying persisted data.
     */
    void setHttpResponseList(String key, PersistedList<HttpResponse> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link HttpResponse}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteHttpResponseList(String key);

    /**
     * Retrieve all keys currently mapped for {@link HttpResponse} Lists.
     *
     * @return Set of keys.
     */
    Set<String> httpResponseListKeys();

    /**
     * {@link HttpRequestResponse} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    HttpRequestResponse getHttpRequestResponse(String key);

    /**
     * Associates the specified {@link HttpRequestResponse} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setHttpRequestResponse(String key, HttpRequestResponse value);

    /**
     * Removes the mapping of the specified key to the {@link HttpRequestResponse}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteHttpRequestResponse(String key);

    /**
     * Retrieve all keys currently mapped for {@link HttpRequestResponse} values.
     *
     * @return Set of keys.
     */
    Set<String> httpRequestResponseKeys();

    /**
     * {@link PersistedList} of {@link HttpRequestResponse} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<HttpRequestResponse> getHttpRequestResponseList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link HttpRequestResponse} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              The methods of this list operate on the underlying persisted data.
     */
    void setHttpRequestResponseList(String key, PersistedList<HttpRequestResponse> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link HttpRequestResponse}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteHttpRequestResponseList(String key);

    /**
     * Retrieve all keys currently mapped for {@link HttpRequestResponse} Lists.
     *
     * @return Set of keys.
     */
    Set<String> httpRequestResponseListKeys();

    /**
     * {@link PersistedList} of {@link Boolean} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value to which the specified key is mapped, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<Boolean> getBooleanList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link Boolean} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setBooleanList(String key, PersistedList<Boolean> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link Boolean}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteBooleanList(String key);

    /**
     * Retrieve all keys currently mapped for {@link Boolean} Lists.
     *
     * @return Set of keys.
     */
    Set<String> booleanListKeys();

    /**
     * {@link PersistedList} of {@link Short} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value to which the specified key is mapped, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<Short> getShortList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link Short} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setShortList(String key, PersistedList<Short> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link Short}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteShortList(String key);

    /**
     * Retrieve all keys currently mapped for {@link Short} Lists.
     *
     * @return Set of keys.
     */
    Set<String> shortListKeys();

    /**
     * {@link PersistedList} of {@link Integer} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value to which the specified key is mapped, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<Integer> getIntegerList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link Integer} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setIntegerList(String key, PersistedList<Integer> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link Integer}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteIntegerList(String key);

    /**
     * Retrieve all keys currently mapped for {@link Integer} Lists.
     *
     * @return Set of keys.
     */
    Set<String> integerListKeys();

    /**
     * {@link PersistedList} of {@link Long} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value to which the specified key is mapped, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<Long> getLongList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link Long} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setLongList(String key, PersistedList<Long> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link Long}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteLongList(String key);

    /**
     * Retrieve all keys currently mapped for {@link Long} Lists.
     *
     * @return Set of keys.
     */
    Set<String> longListKeys();

    /**
     * {@link PersistedList} of {@link String} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value to which the specified key is mapped, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<String> getStringList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@link String} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setStringList(String key, PersistedList<String> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link String}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteStringList(String key);

    /**
     * Retrieve all keys currently mapped for {@link String} Lists.
     *
     * @return Set of keys.
     */
    Set<String> stringListKeys();

    /**
     * {@link PersistedList} of {@link ByteArray} associated with the specified key,
     * or {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    PersistedList<ByteArray> getByteArrayList(String key);

    /**
     * Associates the specified {@link PersistedList} of {@code ByteArray} with the specified key in this map.
     * If the map previously contained a mapping for the key,
     * the old value is replaced by the specified value.
     *
     * @param key   The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              The methods of this list operate on the underlying persisted data.
     */
    void setByteArrayList(String key, PersistedList<ByteArray> value);

    /**
     * Removes the mapping of the specified key to the {@link PersistedList} of {@link ByteArray}.
     *
     * @param key The key whose mapping is to be deleted.
     */
    void deleteByteArrayList(String key);

    /**
     * Retrieve all keys currently mapped for {@link ByteArray} Lists.
     *
     * @return Set of keys.
     */
    Set<String> byteArrayListKeys();

    /**
     * Create a new instance of {@link PersistedObject}.
     *
     * @return A new {@link PersistedObject} instance.
     */
    static PersistedObject persistedObject()
    {
        return FACTORY.persistedObject();
    }
}
