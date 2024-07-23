/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Range of integer values between two values in which the range includes the start value but excludes the end value.
 */
public interface Range
{
    /**
     * @return the inclusive start index
     */
    int startIndexInclusive();

    /**
     * @return the exclusive end index
     */
    int endIndexExclusive();

    /**
     * @param index The index to test.
     *
     * @return True if the index is in the range.
     */
    boolean contains(int index);

    /**
     * Create a range object from two indices.
     *
     * @param startIndexInclusive The start index of the range inclusive of this value.
     * @param endIndexExclusive   The end index of the range exclusive of this value.
     *
     * @return The range.
     */
    static Range range(int startIndexInclusive, int endIndexExclusive)
    {
        return FACTORY.range(startIndexInclusive, endIndexExclusive);
    }
}
