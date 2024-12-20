package burp.vaycore.onescan.common;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * 语言包辅助类
 * <p>
 * Created by vaycore on 2024-12-02.
 */
public class L {

    private static final Locale sDefaultLocale = new Locale("en", "US");
    private static final ResourceBundle sLanguage;

    static {
        // 初始化语言包
        Locale locale = Locale.getDefault();
        ResourceBundle language = ResourceBundle.getBundle("i18n/messages", locale);
        if (!language.containsKey("plugin_name")) {
            language = ResourceBundle.getBundle("i18n/messages", sDefaultLocale);
        }
        sLanguage = language;
    }

    private L() {
        throw new IllegalAccessError("L class not support create instance.");
    }

    /**
     * 获取语言包中 key 对应的内容
     *
     * @param key key
     * @return key 对应的内容
     * @throws IllegalArgumentException key 不存在时抛出该异常
     */
    public static String get(String key) {
        return L.get(key, "");
    }

    /**
     * 获取语言包中 key 对应的内容
     *
     * @param key  key
     * @param args 格式化参数
     * @return key 对应的内容
     * @throws IllegalArgumentException key 不存在时抛出该异常
     */
    public static String get(String key, Object... args) {
        checkKey(key);
        String value = sLanguage.getString(key);
        return String.format(value, args);
    }

    /**
     * 检测语言包中 key 是否存在
     *
     * @param key key
     * @throws IllegalArgumentException key 不存在时抛出该异常
     */
    private static void checkKey(String key) {
        if (!sLanguage.containsKey(key)) {
            Locale l = sLanguage.getLocale();
            String localeStr = l.getLanguage() + "_" + l.getCountry();
            throw new IllegalArgumentException(localeStr + " language '" + key + "' not found!");
        }
    }
}
