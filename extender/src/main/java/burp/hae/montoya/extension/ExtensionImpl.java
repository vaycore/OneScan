package burp.hae.montoya.extension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class ExtensionImpl implements Extension, IExtensionStateListener {

    private final IBurpExtenderCallbacks mCallbacks;
    private ExtensionUnloadingHandler mExtensionUnloadingHandler;

    public ExtensionImpl(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
    }

    @Override
    public void setName(String extensionName) {
        mCallbacks.setExtensionName(extensionName);
    }

    @Override
    public String filename() {
        return mCallbacks.getExtensionFilename();
    }

    @Override
    public boolean isBapp() {
        return mCallbacks.isExtensionBapp();
    }

    @Override
    public void unload() {
        mCallbacks.unloadExtension();
    }

    @Override
    public Registration registerUnloadingHandler(ExtensionUnloadingHandler extensionUnloadingHandler) {
        if (extensionUnloadingHandler == null) {
            return null;
        }
        this.mExtensionUnloadingHandler = extensionUnloadingHandler;
        this.mCallbacks.registerExtensionStateListener(this);
        return new Registration() {
            @Override
            public boolean isRegistered() {
                return mExtensionUnloadingHandler != null;
            }

            @Override
            public void deregister() {
                mCallbacks.removeExtensionStateListener(ExtensionImpl.this);
                mExtensionUnloadingHandler = null;
            }
        };
    }

    @Override
    public void extensionUnloaded() {
        if (mExtensionUnloadingHandler != null) {
            mExtensionUnloadingHandler.extensionUnloaded();
        }
    }
}
