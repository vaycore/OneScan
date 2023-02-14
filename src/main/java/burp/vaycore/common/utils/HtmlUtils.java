package burp.vaycore.common.utils;

import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Html工具类
 * <p>
 * Created by vaycore on 2022-08-11.
 */
public class HtmlUtils {

    /**
     * 网页标题规则
     */
    private static final Pattern sTitleRegex;

    static {
        sTitleRegex = Pattern.compile("<\\s*title.*>([^<]+)<\\s*/\\s*title>",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    }

    private HtmlUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static String findTitleByHtmlBody(byte[] body) {
        return findTitleByHtmlBody(body, "UTF-8");
    }

    public static String findTitleByHtmlBody(byte[] body, String charsetName) {
        if (body == null || body.length == 0) {
            return "";
        }
        Charset charset;
        if (Charset.isSupported(charsetName)) {
            charset = Charset.forName(charsetName);
        } else {
            charset = Charset.defaultCharset();
        }
        String htmlBody = new String(body, charset);
        Matcher matcher = sTitleRegex.matcher(htmlBody);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
}
