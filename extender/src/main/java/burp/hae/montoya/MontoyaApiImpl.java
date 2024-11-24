package burp.hae.montoya;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.comparer.Comparer;
import burp.api.montoya.decoder.Decoder;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.Http;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.organizer.Organizer;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.utilities.Utilities;
import burp.api.montoya.websocket.WebSockets;
import burp.hae.montoya.extension.ExtensionImpl;
import burp.hae.montoya.http.HttpImpl;
import burp.hae.montoya.logging.LoggingImpl;
import burp.hae.montoya.proxy.ProxyImpl;
import burp.hae.montoya.scanner.ScannerImpl;
import burp.hae.montoya.ui.UserInterfaceImpl;
import burp.hae.montoya.utilities.UtilitiesImpl;

/**
 * MontoyaAPI 接口实现
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class MontoyaApiImpl implements MontoyaApi {

    private final ExtensionImpl extension;
    private final Http http;
    private final Logging logging;
    private final Proxy proxy;
    private final UserInterface userInterface;
    private final UtilitiesImpl utilities;
    private final ScannerImpl scanner;

    public MontoyaApiImpl(IBurpExtenderCallbacks callbacks) {
        this.extension = new ExtensionImpl(callbacks);
        this.http = new HttpImpl(callbacks);
        this.logging = new LoggingImpl(callbacks);
        this.proxy = new ProxyImpl(callbacks);
        this.userInterface = new UserInterfaceImpl(callbacks);
        this.utilities = new UtilitiesImpl(callbacks);
        this.scanner = new ScannerImpl(callbacks);
    }

    @Override
    public BurpSuite burpSuite() {
        return null;
    }

    @Override
    public Collaborator collaborator() {
        return null;
    }

    @Override
    public Comparer comparer() {
        return null;
    }

    @Override
    public Decoder decoder() {
        return null;
    }

    @Override
    public Extension extension() {
        return this.extension;
    }

    @Override
    public Http http() {
        return http;
    }

    @Override
    public Intruder intruder() {
        return null;
    }

    @Override
    public Logging logging() {
        return this.logging;
    }

    @Override
    public Organizer organizer() {
        return null;
    }

    @Override
    public Persistence persistence() {
        return null;
    }

    @Override
    public Proxy proxy() {
        return this.proxy;
    }

    @Override
    public Repeater repeater() {
        return null;
    }

    @Override
    public Scanner scanner() {
        return this.scanner;
    }

    @Override
    public Scope scope() {
        return null;
    }

    @Override
    public SiteMap siteMap() {
        return null;
    }

    @Override
    public UserInterface userInterface() {
        return userInterface;
    }

    @Override
    public Utilities utilities() {
        return this.utilities;
    }

    @Override
    public WebSockets websockets() {
        return null;
    }
}
