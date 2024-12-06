package burp.hae.montoya.http;

import burp.IHttpService;
import burp.api.montoya.http.HttpService;
import burp.vaycore.common.utils.IPUtils;
import burp.vaycore.common.utils.StringUtils;

import java.net.InetAddress;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class HttpServiceImpl implements HttpService {

    private final IHttpService httpService;

    public HttpServiceImpl(IHttpService httpService) {
        this.httpService = httpService;
    }

    @Override
    public String host() {
        if (this.httpService == null) {
            return "0.0.0.0";
        }
        String host = this.httpService.getHost();
        if (StringUtils.isEmpty(host)) {
            return "0.0.0.0";
        }
        return host;
    }

    /**
     * @return 范围（1-65535）
     */
    @Override
    public int port() {
        if (this.httpService == null) {
            return 80;
        }
        int port = this.httpService.getPort();
        if (port <= 0 || port > 65535) {
            return this.secure() ? 443 : 80;
        }
        return port;
    }

    @Override
    public boolean secure() {
        if (this.httpService == null) {
            return false;
        }
        return "https".equalsIgnoreCase(this.httpService.getProtocol());
    }

    @Override
    public String ipAddress() {
        String host = this.host();
        // 如果是 IPv4 地址，直接返回
        if (IPUtils.hasIPv4(host)) {
            return host;
        }
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (Exception e) {
            return "0.0.0.0";
        }
    }
}
