package burp.hae.montoya.logging;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.logging.Logging;
import burp.vaycore.common.utils.StringUtils;

import java.io.PrintStream;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class LoggingImpl implements Logging {

    private final IBurpExtenderCallbacks callbacks;
    private final PrintStream stdOut;
    private final PrintStream stdErr;

    public LoggingImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdOut = new PrintStream(this.callbacks.getStdout());
        this.stdErr = new PrintStream(this.callbacks.getStderr());
    }

    @Override
    public PrintStream output() {
        return this.stdOut;
    }

    @Override
    public PrintStream error() {
        return this.stdErr;
    }

    @Override
    public void logToOutput(String message) {
        this.callbacks.printOutput(message);
    }

    @Override
    public void logToError(String message) {
        this.logToError(message, null);
    }

    @Override
    public void logToError(String message, Throwable cause) {
        if (StringUtils.isNotEmpty(message)) {
            this.callbacks.printError(message);
        }
        if (cause != null) {
            cause.printStackTrace(this.stdErr);
        }
    }

    @Override
    public void logToError(Throwable cause) {
        this.logToError(null, cause);
    }

    @Override
    public void raiseDebugEvent(String message) {

    }

    @Override
    public void raiseInfoEvent(String message) {

    }

    @Override
    public void raiseErrorEvent(String message) {

    }

    @Override
    public void raiseCriticalEvent(String message) {

    }
}
