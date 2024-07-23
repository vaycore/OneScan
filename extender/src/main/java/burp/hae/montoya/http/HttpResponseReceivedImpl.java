package burp.hae.montoya.http;

import burp.api.montoya.core.*;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;

import java.util.List;
import java.util.regex.Pattern;

/**
 * <p>
 * Created by vaycore on 2024-05-07.
 */
public class HttpResponseReceivedImpl implements HttpResponseReceived {

    private final HttpRequest request;
    private final HttpResponse response;
    private final Annotations annotations;
    private final ToolType toolType;

    public HttpResponseReceivedImpl(HttpRequest request, HttpResponse response,
                                    Annotations annotations, ToolType toolType) {
        this.request = request;
        this.response = response;
        this.annotations = annotations;
        this.toolType = toolType;
    }

    @Override
    public int messageId() {
        return 0;
    }

    @Override
    public HttpRequest initiatingRequest() {
        return this.request;
    }

    @Override
    public Annotations annotations() {
        return this.annotations;
    }

    @Override
    public ToolSource toolSource() {
        return new ToolSource() {
            @Override
            public ToolType toolType() {
                return HttpResponseReceivedImpl.this.toolType;
            }

            @Override
            public boolean isFromTool(ToolType... toolType) {
                return false;
            }
        };
    }

    @Override
    public short statusCode() {
        return this.response.statusCode();
    }

    @Override
    public String reasonPhrase() {
        return this.response.reasonPhrase();
    }

    @Override
    public boolean isStatusCodeClass(StatusCodeClass statusCodeClass) {
        return this.response.isStatusCodeClass(statusCodeClass);
    }

    @Override
    public String httpVersion() {
        return this.response.httpVersion();
    }

    @Override
    public List<HttpHeader> headers() {
        return this.response.headers();
    }

    @Override
    public boolean hasHeader(HttpHeader header) {
        return this.response.hasHeader(header);
    }

    @Override
    public boolean hasHeader(String name) {
        return this.response.hasHeader(name);
    }

    @Override
    public boolean hasHeader(String name, String value) {
        return this.response.hasHeader(name, value);
    }

    @Override
    public HttpHeader header(String name) {
        return this.response.header(name);
    }

    @Override
    public String headerValue(String name) {
        return this.response.headerValue(name);
    }

    @Override
    public ByteArray body() {
        return this.response.body();
    }

    @Override
    public String bodyToString() {
        return this.response.bodyToString();
    }

    @Override
    public int bodyOffset() {
        return this.response.bodyOffset();
    }

    @Override
    public List<Marker> markers() {
        return this.response.markers();
    }

    @Override
    public List<Cookie> cookies() {
        return this.response.cookies();
    }

    @Override
    public Cookie cookie(String name) {
        return this.response.cookie(name);
    }

    @Override
    public String cookieValue(String name) {
        return this.response.cookieValue(name);
    }

    @Override
    public boolean hasCookie(String name) {
        return this.response.hasCookie(name);
    }

    @Override
    public boolean hasCookie(Cookie cookie) {
        return this.response.hasCookie(cookie);
    }

    @Override
    public MimeType mimeType() {
        return this.response.mimeType();
    }

    @Override
    public MimeType statedMimeType() {
        return this.response.statedMimeType();
    }

    @Override
    public MimeType inferredMimeType() {
        return this.response.inferredMimeType();
    }

    @Override
    public List<KeywordCount> keywordCounts(String... keywords) {
        return this.response.keywordCounts(keywords);
    }

    @Override
    public List<Attribute> attributes(AttributeType... types) {
        return this.response.attributes(types);
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        return this.response.contains(searchTerm, caseSensitive);
    }

    @Override
    public boolean contains(Pattern pattern) {
        return this.response.contains(pattern);
    }

    @Override
    public ByteArray toByteArray() {
        return this.response.toByteArray();
    }

    @Override
    public HttpResponse copyToTempFile() {
        return this.response.copyToTempFile();
    }

    @Override
    public HttpResponse withStatusCode(short statusCode) {
        return this.response.withStatusCode(statusCode);
    }

    @Override
    public HttpResponse withReasonPhrase(String reasonPhrase) {
        return this.response.withReasonPhrase(reasonPhrase);
    }

    @Override
    public HttpResponse withHttpVersion(String httpVersion) {
        return this.response.withHttpVersion(httpVersion);
    }

    @Override
    public HttpResponse withBody(String body) {
        return this.response.withBody(body);
    }

    @Override
    public HttpResponse withBody(ByteArray body) {
        return this.response.withBody(body);
    }

    @Override
    public HttpResponse withAddedHeader(HttpHeader header) {
        return this.response.withAddedHeader(header);
    }

    @Override
    public HttpResponse withAddedHeader(String name, String value) {
        return this.response.withAddedHeader(name, value);
    }

    @Override
    public HttpResponse withUpdatedHeader(HttpHeader header) {
        return this.response.withUpdatedHeader(header);
    }

    @Override
    public HttpResponse withUpdatedHeader(String name, String value) {
        return this.response.withUpdatedHeader(name, value);
    }

    @Override
    public HttpResponse withRemovedHeader(HttpHeader header) {
        return this.response.withRemovedHeader(header);
    }

    @Override
    public HttpResponse withRemovedHeader(String name) {
        return this.response.withRemovedHeader(name);
    }

    @Override
    public HttpResponse withMarkers(List<Marker> markers) {
        return this.response.withMarkers(markers);
    }

    @Override
    public HttpResponse withMarkers(Marker... markers) {
        return this.response.withMarkers(markers);
    }
}
