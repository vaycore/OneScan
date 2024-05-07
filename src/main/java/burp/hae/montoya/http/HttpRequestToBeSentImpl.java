package burp.hae.montoya.http;

import burp.api.montoya.core.*;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;

import java.util.List;
import java.util.regex.Pattern;

/**
 * <p>
 * Created by vaycore on 2024-05-07.
 */
public class HttpRequestToBeSentImpl implements HttpRequestToBeSent {

    private final HttpRequest request;
    private final Annotations annotations;
    private final ToolType toolType;

    public HttpRequestToBeSentImpl(HttpRequest request, Annotations annotations, ToolType toolType) {
        this.request = request;
        this.annotations = annotations;
        this.toolType = toolType;
    }

    @Override
    public int messageId() {
        return 0;
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
                return HttpRequestToBeSentImpl.this.toolType;
            }

            @Override
            public boolean isFromTool(ToolType... toolType) {
                return false;
            }
        };
    }

    @Override
    public boolean isInScope() {
        return this.request.isInScope();
    }

    @Override
    public HttpService httpService() {
        return this.request.httpService();
    }

    @Override
    public String url() {
        return this.request.url();
    }

    @Override
    public String method() {
        return this.request.method();
    }

    @Override
    public String path() {
        return this.request.path();
    }

    @Override
    public String query() {
        return this.request.query();
    }

    @Override
    public String pathWithoutQuery() {
        return this.request.pathWithoutQuery();
    }

    @Override
    public String fileExtension() {
        return this.request.fileExtension();
    }

    @Override
    public String httpVersion() {
        return this.request.httpVersion();
    }

    @Override
    public List<HttpHeader> headers() {
        return this.request.headers();
    }

    @Override
    public boolean hasHeader(HttpHeader header) {
        return this.request.hasHeader(header);
    }

    @Override
    public boolean hasHeader(String name) {
        return this.request.hasHeader(name);
    }

    @Override
    public boolean hasHeader(String name, String value) {
        return this.request.hasHeader(name, value);
    }

    @Override
    public HttpHeader header(String name) {
        return this.request.header(name);
    }

    @Override
    public String headerValue(String name) {
        return this.request.headerValue(name);
    }

    @Override
    public boolean hasParameters() {
        return this.request.hasParameters();
    }

    @Override
    public boolean hasParameters(HttpParameterType type) {
        return this.request.hasParameters(type);
    }

    @Override
    public ParsedHttpParameter parameter(String name, HttpParameterType type) {
        return this.request.parameter(name, type);
    }

    @Override
    public String parameterValue(String name, HttpParameterType type) {
        return this.request.parameterValue(name, type);
    }

    @Override
    public boolean hasParameter(String name, HttpParameterType type) {
        return this.request.hasParameter(name, type);
    }

    @Override
    public boolean hasParameter(HttpParameter parameter) {
        return this.request.hasParameter(parameter);
    }

    @Override
    public ContentType contentType() {
        return this.request.contentType();
    }

    @Override
    public List<ParsedHttpParameter> parameters() {
        return this.request.parameters();
    }

    @Override
    public List<ParsedHttpParameter> parameters(HttpParameterType type) {
        return this.request.parameters(type);
    }

    @Override
    public ByteArray body() {
        return this.request.body();
    }

    @Override
    public String bodyToString() {
        return this.request.bodyToString();
    }

    @Override
    public int bodyOffset() {
        return this.request.bodyOffset();
    }

    @Override
    public List<Marker> markers() {
        return this.request.markers();
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        return this.request.contains(searchTerm, caseSensitive);
    }

    @Override
    public boolean contains(Pattern pattern) {
        return this.request.contains(pattern);
    }

    @Override
    public ByteArray toByteArray() {
        return this.request.toByteArray();
    }

    @Override
    public HttpRequest copyToTempFile() {
        return this.request.copyToTempFile();
    }

    @Override
    public HttpRequest withService(HttpService service) {
        return this.request.withService(service);
    }

    @Override
    public HttpRequest withPath(String path) {
        return this.request.withPath(path);
    }

    @Override
    public HttpRequest withMethod(String method) {
        return this.request.withMethod(method);
    }

    @Override
    public HttpRequest withHeader(HttpHeader header) {
        return this.request.withHeader(header);
    }

    @Override
    public HttpRequest withHeader(String name, String value) {
        return this.request.withHeader(name, value);
    }

    @Override
    public HttpRequest withParameter(HttpParameter parameters) {
        return this.request.withParameter(parameters);
    }

    @Override
    public HttpRequest withAddedParameters(List<? extends HttpParameter> parameters) {
        return this.request.withAddedParameters(parameters);
    }

    @Override
    public HttpRequest withAddedParameters(HttpParameter... parameters) {
        return this.request.withAddedParameters(parameters);
    }

    @Override
    public HttpRequest withRemovedParameters(List<? extends HttpParameter> parameters) {
        return this.request.withRemovedParameters(parameters);
    }

    @Override
    public HttpRequest withRemovedParameters(HttpParameter... parameters) {
        return this.request.withRemovedParameters(parameters);
    }

    @Override
    public HttpRequest withUpdatedParameters(List<? extends HttpParameter> parameters) {
        return this.request.withUpdatedParameters(parameters);
    }

    @Override
    public HttpRequest withUpdatedParameters(HttpParameter... parameters) {
        return this.request.withUpdatedParameters(parameters);
    }

    @Override
    public HttpRequest withTransformationApplied(HttpTransformation transformation) {
        return this.request.withTransformationApplied(transformation);
    }

    @Override
    public HttpRequest withBody(String body) {
        return this.request.withBody(body);
    }

    @Override
    public HttpRequest withBody(ByteArray body) {
        return this.request.withBody(body);
    }

    @Override
    public HttpRequest withAddedHeader(String name, String value) {
        return this.request.withAddedHeader(name, value);
    }

    @Override
    public HttpRequest withAddedHeader(HttpHeader header) {
        return this.request.withAddedHeader(header);
    }

    @Override
    public HttpRequest withUpdatedHeader(String name, String value) {
        return this.request.withUpdatedHeader(name, value);
    }

    @Override
    public HttpRequest withUpdatedHeader(HttpHeader header) {
        return this.request.withUpdatedHeader(header);
    }

    @Override
    public HttpRequest withRemovedHeader(String name) {
        return this.request.withRemovedHeader(name);
    }

    @Override
    public HttpRequest withRemovedHeader(HttpHeader header) {
        return this.request.withRemovedHeader(header);
    }

    @Override
    public HttpRequest withMarkers(List<Marker> markers) {
        return this.request.withMarkers(markers);
    }

    @Override
    public HttpRequest withMarkers(Marker... markers) {
        return this.request.withMarkers(markers);
    }

    @Override
    public HttpRequest withDefaultHeaders() {
        return this.request.withDefaultHeaders();
    }
}
