package burp.vaycore.common.utils;

import java.io.File;

/**
 * 路径工具类
 * <p>
 * Created by vaycore on 2022-08-21.
 */
public class PathUtils {

    private PathUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static String getUserHome() {
        String userHome = System.getProperty("user.home");
        return userHome + File.separator;
    }

    public static String getParent(String path) {
        return getParent(new File(path));
    }

    public static String getParent(File path) {
        return getParentFile(path).getPath();
    }

    public static File getParentFile(String path) {
        return getParentFile(new File(path));
    }

    public static File getParentFile(File path) {
        return path.getParentFile();
    }
}
