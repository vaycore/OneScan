package burp.vaycore.common.utils;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Map;

/**
 * Gson解析库工具类
 * <p>
 * Created by vaycore on 2023-04-18.
 */
public class GsonUtils {

    private static final Gson sGson = new GsonBuilder().disableHtmlEscaping().create();

    private GsonUtils() {
        throw new IllegalAccessError("utils class not support create instance.");
    }

    public static boolean hasJson(String data) {
        try {
            JsonElement element = JsonParser.parseString(data);
            if (element.isJsonObject()) {
                return !element.getAsJsonObject().isEmpty();
            } else if (element.isJsonArray()) {
                return !element.getAsJsonArray().isEmpty();
            }
            return false;
        } catch (JsonSyntaxException e) {
            return false;
        }
    }

    public static String toJson(Object obj) {
        String result = "{}";
        if (obj == null) {
            return result;
        }
        try {
            return sGson.toJson(obj);
        } catch (Exception e) {
            e.printStackTrace();
            return result;
        }
    }

    public static Object toObject(String json) {
        return toObject(json, Object.class);
    }

    public static <T> T toObject(String json, Class<T> clz) {
        if (StringUtils.isEmpty(json)) {
            return null;
        }
        try {
            return sGson.fromJson(json, clz);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Map<String, Object> toMap(String json) {
        return toMap(json, Object.class);
    }

    public static <T> Map<String, T> toMap(String json, Class<T> clz) {
        if (StringUtils.isEmpty(json)) {
            return null;
        }
        try {
            Type type = TypeToken.getParameterized(Map.class, String.class, clz).getType();
            return sGson.fromJson(json, type);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ArrayList<Object> toList(String json) {
        return toList(json, Object.class);
    }

    public static <T> ArrayList<T> toList(String json, Class<T> clz) {
        if (StringUtils.isEmpty(json)) {
            return null;
        }
        try {
            Type type = TypeToken.getParameterized(ArrayList.class, clz).getType();
            return sGson.fromJson(json, type);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
