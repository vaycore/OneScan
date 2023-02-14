package burp.vaycore.common.helper;

import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.IPUtils;
import burp.vaycore.common.utils.StringUtils;
import org.json.JSONObject;

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
        sTree = new JSONObject(json).toMap();
    }

    /**
     * 获取主域名
     *
     * @param fqdn 域名、子域名等（例如：www.baidu.com）
     * @return 主域名（例如：baidu.com）, 获取失败返回传入的fqdn参数
     */
    public static String getDomain(String fqdn) {
        if (IPUtils.hasIPv4(fqdn)) {
            return fqdn;
        }
        String[] split = fqdn.split("\\.");
        List<String> list = Arrays.asList(split);
        LinkedList<String> parts = new LinkedList<>(list);
        String domain = queryDomain(parts, sTree);
        if (StringUtils.isEmpty(domain) || !domain.contains(".")) {
            return fqdn;
        }
        return domain;
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
