package burp.vaycore.common.log;

import burp.vaycore.common.utils.StringUtils;

import java.io.OutputStream;
import java.io.PrintWriter;

/**
 * 日志打印模块
 * <p>
 * Created by vaycore on 2022-01-24.
 */
public class Logger {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static boolean isDebug;

    private Logger() {
        throw new IllegalAccessError("Logger class not support create instance.");
    }

    public static void init(boolean isDebug, OutputStream stdout, OutputStream stderr) {
        if (stdout == null) {
            stdout = System.out;
        }
        if (stderr == null) {
            stderr = System.err;
        }
        Logger.stdout = new PrintWriter(stdout, true);
        Logger.stderr = new PrintWriter(stderr, true);
        Logger.isDebug = isDebug;
    }

    public static void debug(Object log) {
        debug("%s", String.valueOf(log));
    }

    public static void debug(String format, Object... args) {
        if (!isDebug) {
            return;
        }
        if (StringUtils.isEmpty(format)) {
            return;
        }
        stdout.format(format + System.lineSeparator(), args);
    }

    public static void info(String format) {
        info("%s", String.valueOf(format));
    }

    public static void info(String format, Object... args) {
        if (StringUtils.isEmpty(format)) {
            return;
        }
        stdout.format(format + System.lineSeparator(), args);
    }

    public static void error(Object log) {
        error("%s", String.valueOf(log));
    }

    public static void error(String format, Object... args) {
        if (StringUtils.isEmpty(format)) {
            return;
        }
        stderr.format(format + System.lineSeparator(), args);
    }
}
