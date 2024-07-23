package burp.hae.montoya.http;

import burp.IHttpService;
import burp.api.montoya.http.HttpService;

import java.net.InetAddress;
import java.net.UnknownHostException;

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
        return this.httpService.getHost();
    }

    @Override
    public int port() {
        return this.httpService.getPort();
    }

    @Override
    public boolean secure() {
        return "https".equals(httpService.getProtocol());
    }

    @Override
    public String ipAddress() {
        String host = httpService.getHost();
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return "0.0.0.0";
        }
    }
}
