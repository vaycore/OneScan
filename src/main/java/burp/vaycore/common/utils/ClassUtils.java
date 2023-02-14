package burp.vaycore.common.utils;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Class工具类
 * <p>
 * Created by vaycore on 2022-08-10.
 */
public class ClassUtils {

    private ClassUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static Object getValueByFieldId(Object obj, int fieldId) {
        Field[] fields = obj.getClass().getDeclaredFields();
        if (fieldId >= fields.length) {
            return "";
        }
        Field field = fields[fieldId];
        if (field.getType() == int.class) {
            return getFieldIntValue(obj, field);
        } else if (field.getType() == boolean.class) {
            return getFieldBooleanValue(obj, field);
        }
        return getFieldStringValue(obj, field);
    }

    public static Class<?> getTypeByFieldId(Class<?> clz, int fieldId) {
        Field[] fields = clz.getDeclaredFields();
        if (fieldId >= fields.length) {
            return String.class;
        }
        Field field = fields[fieldId];
        // 返回 Integer 类型，否则无法正确排序
        if (field.getType() == int.class) {
            return Integer.class;
        } else if (field.getType() == boolean.class) {
            return Boolean.class;
        }
        return field.getType();
    }

    public static List<Class<?>> getClassList(String packageName) {
        return getClassList(packageName, true);
    }

    public static List<Class<?>> getClassList(String packageName, boolean internal) {
        List<Class<?>> result = new ArrayList<>();
        String pkgPath = packageName.replace(".", "/");
        try {
            Enumeration<URL> res = Thread.currentThread().getContextClassLoader().getResources(pkgPath);
            while (res.hasMoreElements()) {
                URL u = res.nextElement();
                if (u == null) {
                    continue;
                }
                if ("file".equals(u.getProtocol())) {
                    File[] files = new File(u.getPath()).listFiles((pathname) -> {
                        String name = pathname.getName();
                        boolean hasClassFile = pathname.isFile() && name.endsWith(".class");
                        // 是否排除内部类
                        if (hasClassFile && internal) {
                            return !name.contains("$");
                        }
                        return hasClassFile;
                    });
                    if (files == null || files.length == 0) {
                        continue;
                    }
                    for (File file : files) {
                        String fileName = file.getName().replace(".class", "");
                        // 拼接包名.类名
                        String className = packageName + "." + fileName;
                        try {
                            Class<?> clz = Class.forName(className);
                            result.add(clz);
                        } catch (ClassNotFoundException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return result;
        }
    }

    public static <T> T newObjectByClass(Class<T> clz) {
        try {
            Constructor<T> c = clz.getDeclaredConstructor();
            return (T) c.newInstance();
        } catch (Exception e) {
            return null;
        }
    }

    private static int getFieldIntValue(Object obj, Field field) {
        try {
            String value = getFieldStringValue(obj, field);
            return Integer.parseInt(value);
        } catch (Exception e) {
            return 0;
        }
    }

    private static boolean getFieldBooleanValue(Object obj, Field field) {
        try {
            String value = getFieldStringValue(obj, field);
            return Boolean.parseBoolean(value);
        } catch (Exception e) {
            return false;
        }
    }

    private static String getFieldStringValue(Object obj, Field field) {
        field.setAccessible(true);
        try {
            String value = String.valueOf(field.get(obj));
            if ("null".equals(value)) {
                value = "";
            }
            return value;
        } catch (Exception e) {
            return "";
        }
    }
}
