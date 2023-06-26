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
     * @param ip IPv4地址
     * @return true=是；false=否
     */
    public static boolean hasIPv4(String ip) {
        Matcher m = sIPRegex.matcher(ip);
        return m.matches();
    }

    /**
     * 随机IPv4地址
     *
     * @return 返回一个随机IPv4地址
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

    /**
     * 随机内网IPv4地址
     *
     * @return 返回一个随机的内网IPv4地址
     */
    public static String randomIPv4ForLocal() {
        long[][] range = new long[][]{
                {167772161L, 184549375L},
                {2886729728L, 2887778303L},
                {3232235520L, 3232301055L},
        };
        Random random = new Random();
        int index = random.nextInt(3);
        long start = range[index][0];
        int bound = (int) (range[index][1] - range[index][0]);
        return numToIPv4(start + random.nextInt(bound));
    }

    /**
     * 数字转换为IPv4地址
     *
     * @param num 数字
     * @return 返回IPv4地址字符串
     */
    public static String numToIPv4(long num) {
        int[] b = new int[4];
        b[0] = (int) (num >> 24 & 0xFF);
        b[1] = (int) (num >> 16 & 0xFF);
        b[2] = (int) (num >> 8 & 0xFF);
        b[3] = (int) (num & 0xFF);
        return b[0] + "." + b[1] + "." + b[2] + "." + b[3];
    }

    /**
     * IPv4地址转换为数字
     * @param ip IPv4地址
     * @return 数字（转换失败返回：-1）
     */
    public static long ipv4ToNum(String ip) {
        if (StringUtils.isEmpty(ip) || !hasIPv4(ip)) {
            return -1;
        }
        String[] split = ip.split("\\.");
        long result = 0;
        result += Long.parseLong(split[0]) << 24;
        result += Long.parseLong(split[1]) << 16;
        result += Long.parseLong(split[2]) << 8;
        result += Long.parseLong(split[3]);
        return result;
    }
}
