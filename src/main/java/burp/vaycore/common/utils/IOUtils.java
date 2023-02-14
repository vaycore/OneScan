package burp.vaycore.common.utils;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

/**
 * IO工具类
 * <p>
 * Created by vaycore on 2022-01-28.
 */
public class IOUtils {

    private IOUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static void closeIO(Closeable c) {
        try {
            if (c != null) {
                c.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte[] readStream(InputStream is) {
        byte[] result = new byte[0];
        if (is == null) {
            return result;
        }
        ByteArrayOutputStream baos = null;
        try {
            baos = new ByteArrayOutputStream();
            int len;
            byte[] temp = new byte[8192];
            while ((len = is.read(temp)) != -1) {
                baos.write(temp, 0, len);
            }
            baos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return result;
        } finally {
            IOUtils.closeIO(is);
            IOUtils.closeIO(baos);
        }
    }
}
