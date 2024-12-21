package burp.hae.montoya.persistence;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;

/**
 * <p>
 * Created by vaycore on 2024-12-21.
 */
public class PersistenceImpl implements Persistence {

    private final IBurpExtenderCallbacks callbacks;
    private final PersistedObjectImpl extensionData;

    public PersistenceImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.extensionData = new PersistedObjectImpl();
    }

    @Override
    public PersistedObject extensionData() {
        return this.extensionData;
    }

    @Override
    public Preferences preferences() {
        return null;
    }
}
