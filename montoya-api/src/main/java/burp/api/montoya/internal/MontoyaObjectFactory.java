/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.internal;

import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.core.*;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.intruder.*;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.proxy.MessageToBeSentAction;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.menu.BasicMenuItem;
import burp.api.montoya.ui.menu.Menu;
import burp.api.montoya.websocket.BinaryMessageAction;
import burp.api.montoya.websocket.MessageAction;
import burp.api.montoya.websocket.TextMessageAction;

import java.util.List;

public interface MontoyaObjectFactory
{
    HttpService httpService(String baseUrl);

    HttpService httpService(String host, boolean secure);

    HttpService httpService(String host, int port, boolean secure);

    HttpHeader httpHeader(String name, String value);

    HttpHeader httpHeader(String header);

    HttpParameter parameter(String name, String value, HttpParameterType type);

    HttpRequest httpRequest();

    HttpRequest httpRequest(ByteArray request);

    HttpRequest httpRequest(String request);

    HttpRequest httpRequest(HttpService service, ByteArray request);

    HttpRequest httpRequest(HttpService service, String request);

    HttpRequest http2Request(HttpService service, List<HttpHeader> headers, String body);

    HttpRequest http2Request(HttpService service, List<HttpHeader> headers, ByteArray body);

    HttpRequest httpRequestFromUrl(String url);

    HttpResponse httpResponse();

    HttpResponse httpResponse(String response);

    HttpResponse httpResponse(ByteArray response);

    HttpRequestResponse httpRequestResponse(HttpRequest request, HttpResponse response, Annotations annotations);

    HttpRequestResponse httpRequestResponse(HttpRequest request, HttpResponse response);

    Range range(int startIndexInclusive, int endIndexExclusive);

    Annotations annotations();

    Annotations annotations(String notes);

    Annotations annotations(HighlightColor highlightColor);

    Annotations annotations(String notes, HighlightColor highlightColor);

    AuditInsertionPoint auditInsertionPoint(String name, HttpRequest baseRequest, int startIndexInclusive, int endIndexExclusive);

    AuditIssueDefinition auditIssueDefinition(String name, String background, String remediation, AuditIssueSeverity typicalSeverity);

    AuditIssue auditIssue(
            String name,
            String detail,
            String remediation,
            String baseUrl,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence,
            String background,
            String remediationBackground,
            AuditIssueSeverity typicalSeverity,
            List<HttpRequestResponse> requestResponses);

    AuditIssue auditIssue(
            String name,
            String detail,
            String remediation,
            String baseUrl,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence,
            String background,
            String remediationBackground,
            AuditIssueSeverity typicalSeverity,
            HttpRequestResponse... requestResponses);

    Selection selection(ByteArray selectionContents);

    Selection selection(int startIndexInclusive, int endIndexExclusive);

    Selection selection(ByteArray selectionContents, int startIndexInclusive, int endIndexExclusive);

    SecretKey secretKey(String encodedKey);

    ProxyRequestReceivedAction proxyRequestReceivedAction(HttpRequest request, Annotations annotations, MessageReceivedAction action);

    ProxyRequestToBeSentAction proxyRequestToBeSentAction(HttpRequest request, Annotations annotations, MessageToBeSentAction action);

    ProxyResponseToBeSentAction proxyResponseToReturnAction(HttpResponse response, Annotations annotations, MessageToBeSentAction action);

    ProxyResponseReceivedAction proxyResponseReceivedAction(HttpResponse response, Annotations annotations, MessageReceivedAction action);

    RequestToBeSentAction requestResult(HttpRequest request, Annotations annotations);

    ResponseReceivedAction responseResult(HttpResponse response, Annotations annotations);

    HttpRequestTemplate httpRequestTemplate(ByteArray content, List<Range> insertionPointOffsets);

    HttpRequestTemplate httpRequestTemplate(HttpRequest request, List<Range> insertionPointOffsets);

    HttpRequestTemplate httpRequestTemplate(ByteArray content, HttpRequestTemplateGenerationOptions options);

    HttpRequestTemplate httpRequestTemplate(HttpRequest request, HttpRequestTemplateGenerationOptions options);

    PayloadProcessingResult payloadProcessingResult(ByteArray processedPayload, PayloadProcessingAction action);

    InteractionFilter interactionIdFilter(String id);

    InteractionFilter interactionPayloadFilter(String payload);

    SiteMapFilter prefixFilter(String prefix);

    Marker marker(Range range);

    Marker marker(int startIndexInclusive, int endIndexExclusive);

    ByteArray byteArrayOfLength(int length);

    ByteArray byteArray(byte[] bytes);

    ByteArray byteArray(int[] ints);

    ByteArray byteArray(String text);

    TextMessageAction continueWithTextMessage(String payload);

    TextMessageAction dropTextMessage();

    TextMessageAction textMessageAction(String payload, MessageAction action);

    BinaryMessageAction continueWithBinaryMessage(ByteArray payload);

    BinaryMessageAction dropBinaryMessage();

    BinaryMessageAction binaryMessageAction(ByteArray payload, MessageAction action);

    BinaryMessageReceivedAction followUserRulesInitialProxyBinaryMessage(ByteArray payload);

    TextMessageReceivedAction followUserRulesInitialProxyTextMessage(String payload);

    BinaryMessageReceivedAction interceptInitialProxyBinaryMessage(ByteArray payload);

    TextMessageReceivedAction interceptInitialProxyTextMessage(String payload);

    BinaryMessageReceivedAction dropInitialProxyBinaryMessage();

    TextMessageReceivedAction dropInitialProxyTextMessage();

    BinaryMessageReceivedAction doNotInterceptInitialProxyBinaryMessage(ByteArray payload);

    TextMessageReceivedAction doNotInterceptInitialProxyTextMessage(String payload);

    BinaryMessageToBeSentAction continueWithFinalProxyBinaryMessage(ByteArray payload);

    TextMessageToBeSentAction continueWithFinalProxyTextMessage(String payload);

    BinaryMessageToBeSentAction dropFinalProxyBinaryMessage();

    TextMessageToBeSentAction dropFinalProxyTextMessage();

    PersistedObject persistedObject();

    PersistedList<Boolean> persistedBooleanList();

    PersistedList<Short> persistedShortList();

    PersistedList<Integer> persistedIntegerList();

    PersistedList<Long> persistedLongList();

    PersistedList<String> persistedStringList();

    PersistedList<ByteArray> persistedByteArrayList();

    PersistedList<HttpRequest> persistedHttpRequestList();

    PersistedList<HttpResponse> persistedHttpResponseList();

    PersistedList<HttpRequestResponse> persistedHttpRequestResponseList();

    AuditResult auditResult(List<AuditIssue> auditIssues);

    AuditResult auditResult(AuditIssue... auditIssues);

    AuditConfiguration auditConfiguration(BuiltInAuditConfiguration builtInAuditConfiguration);

    CrawlConfiguration crawlConfiguration(String... seedUrls);

    HttpParameter urlParameter(String name, String value);

    HttpParameter bodyParameter(String name, String value);

    HttpParameter cookieParameter(String name, String value);

    GeneratedPayload payload(String payload);

    GeneratedPayload payload(ByteArray payload);

    GeneratedPayload payloadEnd();

    PayloadProcessingResult usePayload(ByteArray processedPayload);

    PayloadProcessingResult skipPayload();

    ProxyRequestToBeSentAction requestFinalInterceptResultContinueWith(HttpRequest request);

    ProxyRequestToBeSentAction requestFinalInterceptResultContinueWith(HttpRequest request, Annotations annotations);

    ProxyRequestToBeSentAction requestFinalInterceptResultDrop();

    ProxyResponseToBeSentAction responseFinalInterceptResultDrop();

    ProxyResponseToBeSentAction responseFinalInterceptResultContinueWith(HttpResponse response, Annotations annotations);

    ProxyResponseToBeSentAction responseFinalInterceptResultContinueWith(HttpResponse response);

    ProxyResponseReceivedAction responseInitialInterceptResultIntercept(HttpResponse response);

    ProxyResponseReceivedAction responseInitialInterceptResultIntercept(HttpResponse response, Annotations annotations);

    ProxyResponseReceivedAction responseInitialInterceptResultDoNotIntercept(HttpResponse response);

    ProxyResponseReceivedAction responseInitialInterceptResultDoNotIntercept(HttpResponse response, Annotations annotations);

    ProxyResponseReceivedAction responseInitialInterceptResultFollowUserRules(HttpResponse response);

    ProxyResponseReceivedAction responseInitialInterceptResultFollowUserRules(HttpResponse response, Annotations annotations);

    ProxyResponseReceivedAction responseInitialInterceptResultDrop();

    ProxyRequestReceivedAction requestInitialInterceptResultIntercept(HttpRequest request);

    ProxyRequestReceivedAction requestInitialInterceptResultIntercept(HttpRequest request, Annotations annotations);

    ProxyRequestReceivedAction requestInitialInterceptResultDoNotIntercept(HttpRequest request);

    ProxyRequestReceivedAction requestInitialInterceptResultDoNotIntercept(HttpRequest request, Annotations annotations);

    ProxyRequestReceivedAction requestInitialInterceptResultFollowUserRules(HttpRequest request);

    ProxyRequestReceivedAction requestInitialInterceptResultFollowUserRules(HttpRequest request, Annotations annotations);

    ProxyRequestReceivedAction requestInitialInterceptResultDrop();

    ResponseReceivedAction responseResult(HttpResponse response);

    RequestToBeSentAction requestResult(HttpRequest request);

    HighlightColor highlightColor(String color);

    ActionResult actionResult(HttpRequest request);

    ActionResult actionResult(HttpRequest request, Annotations annotations);

    Menu menu(String caption);

    BasicMenuItem basicMenuItem(String caption);

    RequestOptions requestOptions();
}
