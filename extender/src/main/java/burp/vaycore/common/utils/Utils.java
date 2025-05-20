package burp.vaycore.common.utils;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.security.MessageDigest;
import java.util.List;

/**
 * 杂项工具类
 * <p>
 * Created by vaycore on 2022-08-08.
 */
public class Utils {

    /**
     * 十六进制字符表
     */
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    /**
     * 随机值的字符表
     */
    private static final char[] RANDOM_CHARS = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
            "0123456789" +
            "abcdefghijklmnopqrstuvwxyz").toCharArray();

    private Utils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    /**
     * 获取剪切板内容
     *
     * @return 返回当前剪切板内容，获取失败返回空字符串
     */
    public static String getSysClipboardText() {
        String result = "";
        Clipboard sysClip = Toolkit.getDefaultToolkit().getSystemClipboard();
        // 获取剪切板中的内容
        Transferable t = sysClip.getContents(null);
        // 检查内容是否是文本类型
        if (t == null || !t.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            return "";
        }
        try {
            result = (String) t.getTransferData(DataFlavor.stringFlavor);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 复制内容到剪切板
     *
     * @param text 复制的内容
     */
    public static void setSysClipboardText(String text) {
        Clipboard sysClip = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection ss = new StringSelection(text);
        sysClip.setContents(ss, null);
    }

    /**
     * 生成随机值
     *
     * @param maxValue 最大值（包含）
     * @return 随机值
     */
    public static int randomInt(int maxValue) {
        int minValue = 0;
        return (int) (minValue + Math.random() * (maxValue - minValue + 1));
    }

    /**
     * 生成 long 类型随机值
     *
     * @param minValue 最小值（包含）
     * @param maxValue 最大值（包含）
     * @return 随机值
     */
    public static long nextLong(long minValue, long maxValue) {
        return (long) (minValue + Math.random() * (maxValue - minValue + 1));
    }

    /**
     * 从列表随机获取一条数据
     *
     * @param list 数据列表
     * @return 返回随机数据
     */
    public static <T> T getRandomItem(List<T> list) {
        if (list == null || list.isEmpty()) {
            return null;
        }
        int r = randomInt(list.size() - 1);
        return list.get(r);
    }

    /**
     * 生成一个随机字符串
     *
     * @param length 字符串长度
     * @return 返回随机字符串
     */
    public static String randomString(int length) {
        if (length <= 0) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int randomIndex = randomInt(RANDOM_CHARS.length - 1);
            result.append(RANDOM_CHARS[randomIndex]);
        }
        return result.toString();
    }

    /**
     * 计算 MD5 值
     *
     * @param bytes 字节数据
     * @return 失败返回空字符串
     */
    public static String md5(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(bytes);
            byte[] digest = md.digest();
            return bytesToHex(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 字节转换为16进制字符串
     *
     * @param bytes 字节数据
     * @return 失败返回空字符串
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[v >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }
}
