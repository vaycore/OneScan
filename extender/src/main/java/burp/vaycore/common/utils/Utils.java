package burp.vaycore.common.utils;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;

/**
 * 杂项工具类
 * <p>
 * Created by vaycore on 2022-08-08.
 */
public class Utils {

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
     * 从列表随机获取一个数据
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
     * @param data 字节数据
     * @return 失败返回空字符串
     */
    public static String bytesToHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        BigInteger bigInt = new BigInteger(1, data);
        return bigInt.toString(16);
    }
}
