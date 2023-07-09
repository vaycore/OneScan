package burp.vaycore.onescan.common;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.vaycore.common.utils.StringUtils;

import java.net.URL;

/**
 * IHttpRequestResponse 接口适配器
 * <p>
 * Created by vaycore on 2023-07-09.
 */
public class HttpReqRespAdapter implements IHttpRequestResponse {

    private byte[] requestBytes;
    private byte[] responseBytes;
    private String comment;
    private String highlight;
    private IHttpService httpServer;

    public HttpReqRespAdapter(String url) throws IllegalArgumentException {
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("url is null");
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException(url + " does not include the protocol.");
        }
        try {
            URL u = new URL(url);
            this.requestBytes = buildRequest(u).toString().getBytes();
            this.responseBytes = new byte[0];
            this.comment = "";
            this.highlight = "";
            this.httpServer = buildHttpServer(u);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private StringBuilder buildRequest(URL url) {
        return new StringBuilder().append("GET ").append(getPathWithQuery(url)).append(" HTTP/1.1").append("\r\n")
                .append("Host: ").append(getHostByUrl(url)).append("\r\n")
                .append("Accept: ").append("text/html,application/xhtml+xml,")
                .append("application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;")
                .append("q=0.8,application/signed-exchange;v=b3;q=0.9").append("\r\n")
                .append("Accept-Language: ").append("zh-CN,zh;q=0.9,en;q=0.8").append("\r\n")
                .append("Accept-Encoding: ").append("gzip, deflate").append("\r\n")
                .append("Origin: ").append("https://www.baidu.com").append("\r\n")
                .append("Cache-Control: ").append("max-age=0").append("\r\n")
                .append("Content-Length: ").append("0").append("\r\n")
                .append("\r\n");
    }

    private String getHostByUrl(URL url) {
        String host = url.getHost();
        int port = url.getPort();
        if (port != -1) {
            host += ":" + port;
        }
        return host;
    }

    private String getPathWithQuery(URL url) {
        String result = url.getPath();
        if (StringUtils.isEmpty(result)) {
            result = "/";
        }
        String query = url.getQuery();
        if (!StringUtils.isEmpty(query)) {
            result += "?" + query;
        }
        return result;
    }

    private IHttpService buildHttpServer(URL url) {
        return new IHttpService() {
            @Override
            public String getHost() {
                return url.getHost();
            }

            @Override
            public int getPort() {
                String protocol = getProtocol();
                int port = url.getPort();
                if (port == -1) {
                    port = protocol.equals("https") ? 443 : 80;
                }
                return port;
            }

            @Override
            public String getProtocol() {
                return url.getProtocol();
            }
        };
    }

    @Override
    public byte[] getRequest() {
        return this.requestBytes;
    }

    @Override
    public void setRequest(byte[] bytes) {
        this.requestBytes = bytes;
    }

    @Override
    public byte[] getResponse() {
        return this.responseBytes;
    }

    @Override
    public void setResponse(byte[] bytes) {
        this.responseBytes = bytes;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String s) {
        this.comment = s;
    }

    @Override
    public String getHighlight() {
        return this.highlight;
    }

    @Override
    public void setHighlight(String s) {
        this.highlight = s;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpServer;
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        this.httpServer = iHttpService;
    }
}
