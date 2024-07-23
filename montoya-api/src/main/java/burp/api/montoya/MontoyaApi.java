/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya;

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

/**
 * This interface is used by Burp Suite to pass a set of methods to extensions that can be used
 * to perform various actions within Burp. When an extension is loaded, Burp invokes its
 * {@link BurpExtension#initialize(MontoyaApi)} method and passes an instance
 * of the {@link MontoyaApi} interface. The extension may then invoke the
 * methods of this interface as required in order to extend Burp's
 * functionality.
 */
public interface MontoyaApi
{
    /**
     * Access functionality related to the Burp Suite application.
     *
     * @return An implementation of the BurpSuite interface which exposes application-level functionality.
     */
    BurpSuite burpSuite();

    /**
     * [Professional only] Access the functionality of the Collaborator.
     *
     * @return An implementation of the Collaborator interface which exposes Collaborator functionality.
     */
    Collaborator collaborator();

    /**
     * Access the functionality of the Comparer.
     *
     * @return An implementation of the Comparer interface which exposes Comparer functionality.
     */
    Comparer comparer();

    /**
     * Access the functionality of the Decoder.
     *
     * @return An implementation of the Decoder interface which exposes Decoder functionality.
     */
    Decoder decoder();

    /**
     * Access functionality related to your extension.
     *
     * @return An implementation of the Extension interface which exposes extension functionality.
     */
    Extension extension();

    /**
     * Access the functionality related to HTTP requests and responses.
     *
     * @return An implementation of the Http interface which exposes http functionality.
     */
    Http http();

    /**
     * Access the functionality of the Intruder.
     *
     * @return An implementation of the Comparer interface which exposes Comparer functionality.
     */
    Intruder intruder();

    /**
     * Access the functionality related to logging and events.
     *
     * @return An implementation of the Logging interface which exposes logging functionality.
     */
    Logging logging();

    /**
     * Access the functionality of the Organizer.
     *
     * @return An implementation of the Organizer interface which exposes Organizer functionality.
     */
    Organizer organizer();

    /**
     * Access the functionality related to persistence.
     *
     * @return An implementation of the Persistence interface which exposes persistence functionality.
     */
    Persistence persistence();

    /**
     * Access the functionality of the Proxy.
     *
     * @return An implementation of the Proxy interface which exposes Proxy functionality.
     */
    Proxy proxy();

    /**
     * Access the functionality of the Repeater.
     *
     * @return An implementation of the Repeater interface which exposes Repeater functionality.
     */
    Repeater repeater();

    /**
     * [Professional only] Access the functionality of the Scanner.
     *
     * @return An implementation of the Scanner interface which exposes Scanner functionality.
     */
    Scanner scanner();

    /**
     * Access the functionality related to Burp's suite-wide target scope.
     *
     * @return An implementation of the Scope interface which exposes scope functionality.
     */
    Scope scope();

    /**
     * Access the functionality of the Site Map.
     *
     * @return An implementation of the SiteMap interface which exposes sitemap functionality.
     */
    SiteMap siteMap();

    /**
     * Access the functionality related to the user interface.
     *
     * @return An implementation of the UserInterface interface which exposes user interface functionality.
     */
    UserInterface userInterface();

    /**
     * Access additional utilities.
     *
     * @return An implementation of the Utilities interface which exposes additional utilities.
     */
    Utilities utilities();

    /**
     * Access the functionality related to WebSockets and messages.
     *
     * @return An implementation of the WebSockets interface which exposes WebSocket functionality.
     */
    WebSockets websockets();
}
