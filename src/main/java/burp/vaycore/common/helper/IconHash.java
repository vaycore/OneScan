package burp.vaycore.common.helper;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * IconHash辅助类
 * <p>
 * Created by vaycore on 2023-05-31.<br>
 * Link: <a href="https://github.com/google/guava">Google Guava</a>
 */
public class IconHash {

    private static final IconHash MURMUR3_32 = new IconHash(0, false);
    private static final int UNSIGNED_MASK = 0xFF;
    private static final int CHUNK_SIZE = 4;
    private static final int C1 = 0xcc9e2d51;
    private static final int C2 = 0x1b873593;
    private final int seed;
    private final boolean supplementaryPlaneFix;

    private IconHash() {
        throw new IllegalAccessError("IconHash class not support create instance.");
    }

    public static String hash(byte[] bodyRaw) {
        return hash(bodyRaw, StandardCharsets.UTF_8);
    }

    public static String hash(byte[] bodyRaw, Charset charset) {
        String b64 = Base64.getMimeEncoder()
                .encodeToString(bodyRaw)
                .replaceAll("\r", "") + "\n";
        int ret = MURMUR3_32.hashString(b64, charset);
        return String.valueOf(ret);
    }

    private IconHash(int seed, boolean supplementaryPlaneFix) {
        this.seed = seed;
        this.supplementaryPlaneFix = supplementaryPlaneFix;
    }

    public int hashString(CharSequence input, Charset charset) {
        if (StandardCharsets.UTF_8.equals(charset)) {
            int utf16Length = input.length();
            int h1 = seed;
            int i = 0;
            int len = 0;

            // This loop optimizes for pure ASCII.
            while (i + 4 <= utf16Length) {
                char c0 = input.charAt(i);
                char c1 = input.charAt(i + 1);
                char c2 = input.charAt(i + 2);
                char c3 = input.charAt(i + 3);
                if (c0 < 0x80 && c1 < 0x80 && c2 < 0x80 && c3 < 0x80) {
                    int k1 = c0 | (c1 << 8) | (c2 << 16) | (c3 << 24);
                    k1 = mixK1(k1);
                    h1 = mixH1(h1, k1);
                    i += 4;
                    len += 4;
                } else {
                    break;
                }
            }

            long buffer = 0;
            int shift = 0;
            for (; i < utf16Length; i++) {
                char c = input.charAt(i);
                if (c < 0x80) {
                    buffer |= (long) c << shift;
                    shift += 8;
                    len++;
                } else if (c < 0x800) {
                    buffer |= charToTwoUtf8Bytes(c) << shift;
                    shift += 16;
                    len += 2;
                } else if (c < Character.MIN_SURROGATE || c > Character.MAX_SURROGATE) {
                    buffer |= charToThreeUtf8Bytes(c) << shift;
                    shift += 24;
                    len += 3;
                } else {
                    int codePoint = Character.codePointAt(input, i);
                    if (codePoint == c) {
                        // not a valid code point; let the JDK handle invalid Unicode
                        return hashBytes(input.toString().getBytes(charset));
                    }
                    i++;
                    buffer |= codePointToFourUtf8Bytes(codePoint) << shift;
                    if (supplementaryPlaneFix) { // bug compatibility: earlier versions did not have this add
                        shift += 32;
                    }
                    len += 4;
                }

                if (shift >= 32) {
                    int k1 = mixK1((int) buffer);
                    h1 = mixH1(h1, k1);
                    buffer = buffer >>> 32;
                    shift -= 32;
                }
            }

            int k1 = mixK1((int) buffer);
            h1 ^= k1;
            return fmix(h1, len);
        } else {
            return hashBytes(input.toString().getBytes(charset));
        }
    }

    private static int fmix(int h1, int length) {
        h1 ^= length;
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;
        return h1;
    }

    private static int mixK1(int k1) {
        k1 *= C1;
        k1 = Integer.rotateLeft(k1, 15);
        k1 *= C2;
        return k1;
    }

    private static int mixH1(int h1, int k1) {
        h1 ^= k1;
        h1 = Integer.rotateLeft(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
        return h1;
    }

    private static long charToTwoUtf8Bytes(char c) {
        // c has at most 11 bits
        return ((0x3L << 6) | (c >>> 6)) | ((0x80 | (0x3F & c)) << 8);
    }

    private static long charToThreeUtf8Bytes(char c) {
        return ((0x7L << 5) | (c >>> 12))
                | ((0x80 | (0x3F & (c >>> 6))) << 8)
                | ((0x80 | (0x3F & c)) << 16);
    }

    public int hashBytes(byte[] input) {
        return hashBytes(input, 0, input.length);
    }

    public int hashBytes(byte[] input, int off, int len) {
        checkPositionIndexes(off, off + len, input.length);
        int h1 = seed;
        int i;
        for (i = 0; i + CHUNK_SIZE <= len; i += CHUNK_SIZE) {
            int k1 = mixK1(getIntLittleEndian(input, off + i));
            h1 = mixH1(h1, k1);
        }

        int k1 = 0;
        for (int shift = 0; i < len; i++, shift += 8) {
            k1 ^= toInt(input[off + i]) << shift;
        }
        h1 ^= mixK1(k1);
        return fmix(h1, len);
    }

    private static int toInt(byte value) {
        return value & UNSIGNED_MASK;
    }

    private static int getIntLittleEndian(byte[] input, int offset) {
        return fromBytes(input[offset + 3], input[offset + 2], input[offset + 1], input[offset]);
    }

    private static int fromBytes(byte b1, byte b2, byte b3, byte b4) {
        return b1 << 24 | (b2 & 0xFF) << 16 | (b3 & 0xFF) << 8 | (b4 & 0xFF);
    }

    private static void checkPositionIndexes(int start, int end, int size) {
        // Carefully optimized for execution by hotspot (explanatory comment above)
        if (start < 0 || end < start || end > size) {
            throw new IndexOutOfBoundsException(badPositionIndexes(start, end, size));
        }
    }

    private static String badPositionIndexes(int start, int end, int size) {
        if (start < 0 || start > size) {
            return badPositionIndex(start, size, "start index");
        }
        if (end < 0 || end > size) {
            return badPositionIndex(end, size, "end index");
        }
        // end < start
        return lenientFormat("end index (%s) must not be less than start index (%s)", end, start);
    }

    private static String badPositionIndex(int index, int size, String desc) {
        if (index < 0) {
            return lenientFormat("%s (%s) must not be negative", desc, index);
        } else if (size < 0) {
            throw new IllegalArgumentException("negative size: " + size);
        } else { // index > size
            return lenientFormat("%s (%s) must not be greater than size (%s)", desc, index, size);
        }
    }

    private static String lenientFormat(String template, Object... args) {
        template = String.valueOf(template); // null -> "null"

        if (args == null) {
            args = new Object[]{"(Object[])null"};
        } else {
            for (int i = 0; i < args.length; i++) {
                args[i] = lenientToString(args[i]);
            }
        }

        // start substituting the arguments into the '%s' placeholders
        StringBuilder builder = new StringBuilder(template.length() + 16 * args.length);
        int templateStart = 0;
        int i = 0;
        while (i < args.length) {
            int placeholderStart = template.indexOf("%s", templateStart);
            if (placeholderStart == -1) {
                break;
            }
            builder.append(template, templateStart, placeholderStart);
            builder.append(args[i++]);
            templateStart = placeholderStart + 2;
        }
        builder.append(template, templateStart, template.length());

        // if we run out of placeholders, append the extra args in square braces
        if (i < args.length) {
            builder.append(" [");
            builder.append(args[i++]);
            while (i < args.length) {
                builder.append(", ");
                builder.append(args[i++]);
            }
            builder.append(']');
        }

        return builder.toString();
    }

    private static String lenientToString(Object o) {
        if (o == null) {
            return "null";
        }
        try {
            return o.toString();
        } catch (Exception e) {
            // Default toString() behavior - see Object.toString()
            String objectToString =
                    o.getClass().getName() + '@' + Integer.toHexString(System.identityHashCode(o));
            return "<" + objectToString + " threw " + e.getClass().getName() + ">";
        }
    }

    private static long codePointToFourUtf8Bytes(int codePoint) {
        // codePoint has at most 21 bits
        return ((0xFL << 4) | (codePoint >>> 18))
                | ((0x80L | (0x3F & (codePoint >>> 12))) << 8)
                | ((0x80L | (0x3F & (codePoint >>> 6))) << 16)
                | ((0x80L | (0x3F & codePoint)) << 24);
    }
}
