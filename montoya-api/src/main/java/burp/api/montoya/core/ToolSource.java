/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

/**
 * Tool that is the source of an object.
 */
public interface ToolSource
{
    /**
     * @return the tool type.
     */
    ToolType toolType();

    /**
     * Determine whether this tool source is from a specified tool.
     *
     * @param toolType The tool types to check.
     *
     * @return Returns {@code true} if this tool source is from any of the
     * specified tool types.
     */
    boolean isFromTool(ToolType... toolType);
}
