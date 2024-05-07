package burp.hae.montoya.utilities;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.utilities.*;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class UtilitiesImpl implements Utilities {

    private final ByteUtilsImpl byteUtils;

    public UtilitiesImpl(IBurpExtenderCallbacks callbacks) {
        this.byteUtils = new ByteUtilsImpl(callbacks);
    }

    @Override
    public Base64Utils base64Utils() {
        return null;
    }

    @Override
    public ByteUtilsImpl byteUtils() {
        return byteUtils;
    }

    @Override
    public CompressionUtils compressionUtils() {
        return null;
    }

    @Override
    public CryptoUtils cryptoUtils() {
        return null;
    }

    @Override
    public HtmlUtils htmlUtils() {
        return null;
    }

    @Override
    public NumberUtils numberUtils() {
        return null;
    }

    @Override
    public RandomUtils randomUtils() {
        return null;
    }

    @Override
    public StringUtils stringUtils() {
        return null;
    }

    @Override
    public URLUtils urlUtils() {
        return null;
    }
}
