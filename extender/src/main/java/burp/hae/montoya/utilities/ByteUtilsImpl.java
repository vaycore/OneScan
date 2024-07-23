package burp.hae.montoya.utilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.api.montoya.utilities.ByteUtils;

import java.util.regex.Pattern;

/**
 * <p>
 * Created by vaycore on 2024-05-06.
 */
public class ByteUtilsImpl implements ByteUtils {

    private final IExtensionHelpers helpers;

    public ByteUtilsImpl(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public int indexOf(byte[] data, byte[] searchTerm) {
        return this.indexOf(data, searchTerm, false);
    }

    @Override
    public int indexOf(byte[] data, byte[] searchTerm, boolean caseSensitive) {
        return this.indexOf(data, searchTerm, caseSensitive, 0, data.length);
    }

    @Override
    public int indexOf(byte[] data, byte[] searchTerm, boolean caseSensitive, int from, int to) {
        return this.helpers.indexOf(data, searchTerm, caseSensitive, from, to);
    }

    @Override
    public int indexOf(byte[] data, Pattern pattern) {
        return 0;
    }

    @Override
    public int indexOf(byte[] data, Pattern pattern, int from, int to) {
        return 0;
    }

    @Override
    public int countMatches(byte[] data, byte[] searchTerm) {
        return 0;
    }

    @Override
    public int countMatches(byte[] data, byte[] searchTerm, boolean caseSensitive) {
        return 0;
    }

    @Override
    public int countMatches(byte[] data, byte[] searchTerm, boolean caseSensitive, int from, int to) {
        return 0;
    }

    @Override
    public int countMatches(byte[] data, Pattern pattern) {
        return 0;
    }

    @Override
    public int countMatches(byte[] data, Pattern pattern, int from, int to) {
        return 0;
    }

    @Override
    public String convertToString(byte[] bytes) {
        return this.helpers.bytesToString(bytes);
    }

    @Override
    public byte[] convertFromString(String string) {
        return this.helpers.stringToBytes(string);
    }
}
