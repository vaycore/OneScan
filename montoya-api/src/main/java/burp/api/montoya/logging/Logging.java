/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.logging;

import java.io.PrintStream;

/**
 * Provides access to the functionality related to logging and events.
 */
public interface Logging
{
    /**
     * Obtain the current extension's standard output
     * stream. Extensions should write all output to this stream, allowing the
     * Burp user to configure how that output is handled from within the UI.
     *
     * @return The extension's standard output stream.
     *
     * @deprecated Use {@link Logging#logToOutput} instead.
     */
    @Deprecated
    PrintStream output();

    /**
     * Obtain the current extension's standard error
     * stream. Extensions should write all error messages to this stream,
     * allowing the Burp user to configure how that output is handled from
     * within the UI.
     *
     * @return The extension's standard error stream.
     *
     * @deprecated Use {@link Logging#logToError} instead.
     */
    @Deprecated
    PrintStream error();

    /**
     * This method prints a line of output to the current extension's standard
     * output stream.
     *
     * @param message The message to print.
     */
    void logToOutput(String message);

    /**
     * This method prints a line of output to the current extension's standard
     * error stream.
     *
     * @param message The message to print.
     */
    void logToError(String message);

    /**
     * This method prints a message and a stack trace to the current extension's standard
     * error stream.
     *
     * @param message The message to print.
     * @param cause The cause of the error being logged.
     */
    void logToError(String message, Throwable cause);

    /**
     * This method prints a stack trace to the current extension's standard
     * error stream.
     *
     * @param cause The cause of the error being logged.
     */
    void logToError(Throwable cause);

    /**
     * This method can be used to display a debug event in the Burp Suite
     * event log.
     *
     * @param message The debug message to display.
     */
    void raiseDebugEvent(String message);

    /**
     * This method can be used to display an informational event in the Burp
     * Suite event log.
     *
     * @param message The informational message to display.
     */
    void raiseInfoEvent(String message);

    /**
     * This method can be used to display an error event in the Burp Suite
     * event log.
     *
     * @param message The error message to display.
     */
    void raiseErrorEvent(String message);

    /**
     * This method can be used to display a critical event in the Burp Suite
     * event log.
     *
     * @param message The critical message to display.
     */
    void raiseCriticalEvent(String message);
}
