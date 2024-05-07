package burp.hae.montoya.extension;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class ExtensionImpl implements Extension {

    private final IBurpExtenderCallbacks callbacks;

    public ExtensionImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void setName(String extensionName) {
        this.callbacks.setExtensionName(extensionName);
    }

    @Override
    public String filename() {
        return this.callbacks.getExtensionFilename();
    }

    @Override
    public boolean isBapp() {
        return this.callbacks.isExtensionBapp();
    }

    @Override
    public void unload() {
        this.callbacks.unloadExtension();
    }

    @Override
    public Registration registerUnloadingHandler(ExtensionUnloadingHandler extensionUnloadingHandler) {
        return null;
    }
}
