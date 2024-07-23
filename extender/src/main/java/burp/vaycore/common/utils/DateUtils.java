package burp.vaycore.common.utils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 日期时间工具类
 * <p>
 * Created by vaycore on 2022-01-27.
 */
public class DateUtils {

    private DateUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static String getCurrentDate(String dateFormat) {
        SimpleDateFormat sdf = new SimpleDateFormat(dateFormat, Locale.CHINA);
        return sdf.format(new Date());
    }

    public static long getTimestamp() {
        return System.currentTimeMillis() / 1000;
    }
}
