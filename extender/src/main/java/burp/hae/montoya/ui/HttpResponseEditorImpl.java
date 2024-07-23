package burp.hae.montoya.ui;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.hae.MessageEditorController;

import java.awt.*;
import java.util.Optional;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class HttpResponseEditorImpl implements HttpResponseEditor {

    private final IMessageEditor editor;
    private final MessageEditorController controller;
    private HttpResponse response;

    public HttpResponseEditorImpl(IBurpExtenderCallbacks callbacks, MessageEditorController controller) {
        this.editor = callbacks.createMessageEditor(controller, false);
        this.controller = controller;
    }

    @Override
    public HttpResponse getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(HttpResponse response) {
        byte[] message = response.toByteArray().getBytes();
        this.response = response;
        this.editor.setMessage(message, false);
        this.controller.setResponse(message);
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
