/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.persistence;

import java.util.Set;

/**
 * Enables data to be stored and accessed from the Java preference store. Supports primitives.
 */
public interface Preferences
{
    /**
     * {@link String} associated with the specified key.
     * Returns {@code null} if this map contains no mapping for the key.
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
     * @param key  The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     */
    void setString(String key, String value);

    /**
     * Removes the mapping from the specified key to the {@link String}.
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
     * {@link Boolean} associated with the specified key.
     * Returns {@code null} if this map contains no mapping for the key.
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
     * @param key  The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
     */
    void setBoolean(String key, boolean value);

    /**
     * Removes the mapping from the specified key to the {@link Boolean}.
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
     * {@link Byte} associated with the specified key.
     * Returns {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Byte getByte(String key);

    /**
     * Associates the specified {@code byte} with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key  The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
     */
    void setByte(String key, byte value);

    /**
     * Removes the mapping from the specified key to the {@link Byte}.
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
     * {@link Short} associated with the specified key.
     * Returns {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Short getShort(String key);

    /**
     * Associates the specified short with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key  The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value that is currently mapped to the specified key is removed.
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
     * {@link Integer} associated with the specified key.
     * Returns {@code null} if this map contains no mapping for the key.
     *
     * @param key The key whose associated value is to be returned.
     *
     * @return The value associated with the specified key, or
     * {@code null} if this map contains no mapping for the key.
     */
    Integer getInteger(String key);

    /**
     * Associates the specified {@code int}  with the specified key in this map.
     * This is an optional operation.  If the map previously contained a mapping for
     * the key, the old value is replaced by the specified value.
     *
     * @param key  The key with which the specified value is to be associated.
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
     * @param key  The key with which the specified value is to be associated.
     * @param value The value to be associated with the specified key.
     *              If this value is {@code null} then any value currently mapped to the specified key is removed.
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
}
