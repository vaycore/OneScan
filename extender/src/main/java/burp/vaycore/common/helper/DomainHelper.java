package burp.vaycore.common.helper;

import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.common.utils.IPUtils;
import burp.vaycore.common.utils.StringUtils;

import java.io.InputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * 域名辅助类
 * <p>
 * Created by vaycore on 2022-08-31.
 */
public class DomainHelper {

    private static Map<String, Object> sTree;

    private DomainHelper() {
        throw new IllegalAccessError("DomainHelper class not support create instance.");
    }

    /**
     * 初始化
     *
     * @param resName 数据源的文件名（程序包的resources目录下的文件名）
     */
    public static void init(String resName) {
        InputStream is = DomainHelper.class.getClassLoader().getResourceAsStream(resName);
        String json = FileUtils.readStreamToString(is);
        sTree = GsonUtils.toMap(json);
    }

    /**
     * 获取主域名
     *
     * @param fqdn 域名、子域名等（例如：www.baidu.com）
     * @return 主域名（例如：baidu.com）, 获取失败返回传入的fqdn参数
     */
    public static String getDomain(String fqdn) {
        return getDomain(fqdn, fqdn);
    }

    /**
     * 获取主域名
     *
     * @param fqdn     域名、子域名等（例如：www.baidu.com）
     * @param defValue 获取失败的默认返回值
     * @return 主域名（例如：baidu.com）, 获取失败返回defValue参数
     */
    public static String getDomain(String fqdn, String defValue) {
        if (IPUtils.hasIPv4(fqdn)) {
            return defValue;
        }
        String[] split = fqdn.split("\\.");
        List<String> list = Arrays.asList(split);
        LinkedList<String> parts = new LinkedList<>(list);
        String domain = queryDomain(parts, sTree);
        if (StringUtils.isEmpty(domain) || !domain.contains(".")) {
            return defValue;
        }
        return domain;
    }

    /**
     * 获取主域名的名称
     *
     * @param fqdn 域名、子域名等（例如：www.baidu.com）
     * @return 主域名的名称（例如：baidu）, 获取失败返回传入的fqdn参数
     */
    public static String getDomainName(String fqdn) {
        return getDomainName(fqdn, fqdn);
    }

    /**
     * 获取主域名的名称
     *
     * @param fqdn 域名、子域名等（例如：www.baidu.com）
     * @return 主域名的名称（例如：baidu）, 获取失败返回传入的fqdn参数
     */
    public static String getDomainName(String fqdn, String defValue) {
        String domain = getDomain(fqdn, null);
        if (domain == null) {
            return defValue;
        }
        return domain.split("\\.")[0];
    }

    private static String queryDomain(LinkedList<String> parts, Map<String, Object> node) {
        if (parts.size() == 0) {
            return null;
        }
        String sub = parts.removeLast();
        String result;
        if (node.get("!") != null) {
            return "";
        } else if (node.get(sub) != null) {
            result = queryDomain(parts, (Map<String, Object>) node.get(sub));
        } else if (node.get("*") != null) {
            result = queryDomain(parts, (Map<String, Object>) node.get("*"));
        } else {
            return sub;
        }
        if (result == null) {
            return null;
        } else if (result.equals("")) {
            return sub;
        } else {
            return result + "." + sub;
        }
    }
}
