package burp.hae.montoya.http;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;

import java.util.List;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class HttpImpl implements Http {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private HttpHandler httpHandler;

    public HttpImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public Registration registerHttpHandler(HttpHandler handler) {
        this.httpHandler = handler;
        return new Registration() {
            @Override
            public boolean isRegistered() {
                return HttpImpl.this.httpHandler != null;
            }

            @Override
            public void deregister() {
                HttpImpl.this.httpHandler = null;
            }
        };
    }

    public HttpHandler httpHandler() {
        return httpHandler;
    }

    @Override
    public Registration registerSessionHandlingAction(SessionHandlingAction sessionHandlingAction) {
        return null;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        HttpService httpService = request.httpService();
        IHttpService service = this.helpers.buildHttpService(httpService.host(), httpService.port(),
                httpService.secure());
        IHttpRequestResponse httpReqResp = this.callbacks.makeHttpRequest(service, request.toByteArray().getBytes());
        return buildHttpRequestResponse(httpReqResp);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return null;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return null;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return null;
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        return null;
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) {
        return null;
    }

    @Override
    public ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords) {
        return null;
    }

    @Override
    public ResponseVariationsAnalyzer createResponseVariationsAnalyzer() {
        return null;
    }

    @Override
    public CookieJar cookieJar() {
        return null;
    }

    /**
     * 构建 Montoya 请求响应实例
     *
     * @param httpReqResp 请求响应
     * @return 请求响应实例
     */
    public static HttpRequestResponse buildHttpRequestResponse(IHttpRequestResponse httpReqResp) {
        HttpRequest request = HttpRequest.httpRequest(ByteArray.byteArray(httpReqResp.getRequest()));
        // 可能为空
        byte[] respRaw = httpReqResp.getResponse();
        if (respRaw == null || respRaw.length == 0) {
            respRaw = new byte[0];
        }
        HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(respRaw));
        return HttpRequestResponse.httpRequestResponse(request, response);
    }
}
