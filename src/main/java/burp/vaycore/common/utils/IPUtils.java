package burp.vaycore.common.utils;

import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IP工具类
 * <p>
 * Created by vaycore on 2022-08-31.
 */
public class IPUtils {

    private static final Pattern sIPRegex;

    static {
        sIPRegex = Pattern.compile("^((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}$");
    }

    private IPUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    /**
     * 检测是否为IPv4地址
     *
     * @param ip IP地址
     * @return true=是；false=否
     */
    public static boolean hasIPv4(String ip) {
        Matcher m = sIPRegex.matcher(ip);
        return m.matches();
    }

    /**
     * 随机IP地址
     *
     * @return 返回一个随机IP地址
     */
    public static String randomIPv4() {
        String[] ipv4 = new String[4];
        Random r = new Random();
        for (int i = 0; i < ipv4.length; i++) {
            int randInt = r.nextInt(255) + 1;
            ipv4[i] = String.valueOf(randInt);
        }
        return StringUtils.join(ipv4, ".");
    }
}
