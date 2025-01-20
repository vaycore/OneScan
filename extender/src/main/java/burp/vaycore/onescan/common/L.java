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
    private static final String sBaseName = "i18n/messages";
    private static final ResourceBundle sLanguage;

    static {
        // 初始化语言包
        Locale locale = Locale.getDefault();
        ResourceBundle language;
        try {
            language = ResourceBundle.getBundle(sBaseName, locale);
            if (!language.containsKey("plugin_name")) {
                throw new IllegalStateException("Unable to identify language resource package");
            }
        } catch (Exception e) {
            language = ResourceBundle.getBundle(sBaseName, sDefaultLocale);
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
        // 如果当前语言资源包找不到对应的值，到默认语言资源包里找
        if (!sLanguage.containsKey(key)) {
            ResourceBundle defaultLanguage = ResourceBundle.getBundle(sBaseName, sDefaultLocale);
            if (!defaultLanguage.containsKey(key)) {
                return "Null";
            }
            return defaultLanguage.getString(key);
        }
        String value = sLanguage.getString(key);
        return String.format(value, args);
    }
}
