package burp.hae.montoya.ui;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.*;
import burp.api.montoya.ui.editor.extension.*;
import burp.api.montoya.ui.menu.MenuBar;
import burp.api.montoya.ui.swing.SwingUtils;
import burp.hae.MessageEditorController;

import java.awt.*;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class UserInterfaceImpl implements UserInterface {

    private final IBurpExtenderCallbacks callbacks;
    private ExtensionProvidedHttpRequestEditor httpRequestEditor;
    private ExtensionProvidedHttpResponseEditor httpResponseEditor;
    private final MessageEditorController messageEditorController;

    public UserInterfaceImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.messageEditorController = new MessageEditorController();
    }

    @Override
    public MenuBar menuBar() {
        return null;
    }

    @Override
    public Registration registerSuiteTab(String title, Component component) {
        this.callbacks.customizeUiComponent(component);
        return null;
    }

    @Override
    public Registration registerContextMenuItemsProvider(ContextMenuItemsProvider provider) {
        return null;
    }

    @Override
    public Registration registerHttpRequestEditorProvider(HttpRequestEditorProvider provider) {
        EditorCreationContextImpl context = new EditorCreationContextImpl(ToolType.PROXY);
        httpRequestEditor = provider.provideHttpRequestEditor(context);
        return new Registration() {
            @Override
            public boolean isRegistered() {
                return UserInterfaceImpl.this.httpRequestEditor != null;
            }

            @Override
            public void deregister() {
                UserInterfaceImpl.this.httpRequestEditor = null;
            }
        };
    }

    @Override
    public Registration registerHttpResponseEditorProvider(HttpResponseEditorProvider provider) {
        EditorCreationContextImpl context = new EditorCreationContextImpl(ToolType.PROXY);
        httpResponseEditor = provider.provideHttpResponseEditor(context);
        return new Registration() {
            @Override
            public boolean isRegistered() {
                return UserInterfaceImpl.this.httpResponseEditor != null;
            }

            @Override
            public void deregister() {
                UserInterfaceImpl.this.httpResponseEditor = null;
            }
        };
    }

    @Override
    public Registration registerWebSocketMessageEditorProvider(WebSocketMessageEditorProvider provider) {
        return null;
    }

    @Override
    public RawEditor createRawEditor(EditorOptions... options) {
        return null;
    }

    @Override
    public WebSocketMessageEditor createWebSocketMessageEditor(EditorOptions... options) {
        return null;
    }

    @Override
    public HttpRequestEditor createHttpRequestEditor(EditorOptions... options) {
        return new HttpRequestEditorImpl(this.callbacks, this.messageEditorController);
    }

    @Override
    public HttpResponseEditor createHttpResponseEditor(EditorOptions... options) {
        return new HttpResponseEditorImpl(this.callbacks, this.messageEditorController);
    }

    @Override
    public void applyThemeToComponent(Component component) {

    }

    @Override
    public Theme currentTheme() {
        return null;
    }

    @Override
    public Font currentEditorFont() {
        return null;
    }

    @Override
    public Font currentDisplayFont() {
        return null;
    }

    @Override
    public SwingUtils swingUtils() {
        return null;
    }
}
