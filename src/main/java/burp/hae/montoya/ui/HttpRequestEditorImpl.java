package burp.hae.montoya.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.hae.MessageEditorController;

import java.awt.*;
import java.util.Optional;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class HttpRequestEditorImpl implements HttpRequestEditor {

    private final IExtensionHelpers helpers;
    private final IMessageEditor editor;
    private final MessageEditorController controller;
    private HttpRequest request;

    public HttpRequestEditorImpl(IBurpExtenderCallbacks callbacks, MessageEditorController controller) {
        this.helpers = callbacks.getHelpers();
        this.editor = callbacks.createMessageEditor(controller, false);
        this.controller = controller;
    }

    @Override
    public HttpRequest getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(HttpRequest request) {
        byte[] message = request.toByteArray().getBytes();
        HttpService service = request.httpService();
        this.request = request;
        this.editor.setMessage(message, true);
        // 设置 HttpServer
        if (service != null) {
            IHttpService httpService = this.helpers.buildHttpService(service.host(), service.port(), service.secure());
            this.controller.setHttpService(httpService);
        }
        this.controller.setRequest(message);
    }

    @Override
    public void setSearchExpression(String expression) {

    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public int caretPosition() {
        return 0;
    }

    @Override
    public Optional<Selection> selection() {
        int[] bounds = this.editor.getSelectionBounds();
        return Optional.of(Selection.selection(bounds[0], bounds[1]));
    }

    @Override
    public Component uiComponent() {
        return this.editor.getComponent();
    }
}
