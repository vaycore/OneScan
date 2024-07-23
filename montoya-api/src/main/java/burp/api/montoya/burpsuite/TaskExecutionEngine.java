/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.burpsuite;

/**
 * Provides access to the task execution engine.
 */
public interface TaskExecutionEngine
{
    /**
     * Task execution engine state
     */
    enum TaskExecutionEngineState
    {
        RUNNING, PAUSED
    }

    /**
     * Retrieves the current state of the task execution engine.
     *
     * @return current state
     */
    TaskExecutionEngineState getState();

    /**
     * Sets the task execution engine state
     *
     * @param state new state
     */
    void setState(TaskExecutionEngineState state);
}
