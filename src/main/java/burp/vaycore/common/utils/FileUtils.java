package burp.vaycore.common.utils;

import java.io.*;
import java.util.ArrayList;

/**
 * 文件工具类
 * <p>
 * Created by vaycore on 2022-08-07.
 */
public class FileUtils {

    private FileUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static boolean exists(String path) {
        return exists(new File(path));
    }

    public static boolean exists(File file) {
        return file != null && file.exists();
    }

    public static boolean isFile(String path) {
        return isFile(new File(path));
    }

    public static boolean isFile(File file) {
        return exists(file) && file.isFile();
    }

    public static boolean isDir(String path) {
        return isDir(new File(path));
    }

    public static boolean isDir(File file) {
        return exists(file) && file.isDirectory();
    }

    public static boolean mkdirs(String path) {
        return mkdirs(new File(path));
    }

    public static boolean mkdirs(File file) {
        return file != null && file.mkdirs();
    }

    public static boolean writeFile(InputStream is, String filepath) {
        return writeFile(is, new File(filepath));
    }

    public static boolean writeFile(InputStream is, File file) {
        if (is == null) {
            return false;
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            int len;
            byte[] temp = new byte[8192];
            while ((len = is.read(temp)) != -1) {
                fos.write(temp, 0, len);
            }
            fos.flush();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            IOUtils.closeIO(fos);
            IOUtils.closeIO(is);
        }
    }

    public static boolean writeFile(String filepath, String content) {
        return writeFile(new File(filepath), content, false);
    }

    public static boolean writeFile(String filepath, String content, boolean append) {
        return writeFile(new File(filepath), content, append);
    }

    public static boolean writeFile(File file, String content, boolean append) {
        FileWriter writer = null;
        try {
            writer = new FileWriter(file, append);
            writer.write(content);
            writer.flush();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } finally {
            IOUtils.closeIO(writer);
        }
    }

    public static byte[] readFile(String filepath) {
        byte[] result = new byte[0];
        if (!isFile(filepath)) {
            return result;
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filepath);
            return IOUtils.readStream(fis);
        } catch (IOException e) {
            e.printStackTrace();
            return result;
        } finally {
            IOUtils.closeIO(fis);
        }
    }

    public static String readFileToString(String filepath) {
        byte[] result = readFile(filepath);
        return new String(result, 0, result.length);
    }

    public static String readStreamToString(InputStream is) {
        byte[] result = IOUtils.readStream(is);
        return new String(result, 0, result.length);
    }

    public static ArrayList<String> readFileToList(String filepath) {
        return readFileToList(new File(filepath));
    }

    public static ArrayList<String> readFileToList(File file) {
        if (file == null || !file.exists() || !isFile(file)) {
            return null;
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return readStreamToList(fis);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            IOUtils.closeIO(fis);
        }
    }

    public static ArrayList<String> readStreamToList(InputStream is) {
        if (is == null) {
            return null;
        }
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(is));
            ArrayList<String> lines = new ArrayList<>();
            while (br.ready()) {
                String line = br.readLine();
                if (StringUtils.isNotEmpty(line)) {
                    lines.add(line);
                }
            }
            return lines;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            IOUtils.closeIO(br);
            IOUtils.closeIO(is);
        }
    }

    public static void deleteFile(String filepath) {
        deleteFile(new File(filepath));
    }

    public static void deleteFile(File file) {
        if (!file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files == null || files.length == 0) {
                return;
            }
            for (File fileItem : files) {
                deleteFile(fileItem);
            }
        } else {
            boolean delete = file.delete();
        }
    }
}
