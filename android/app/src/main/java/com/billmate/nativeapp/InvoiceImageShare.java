package com.billmate.nativeapp;

import java.io.IOException;
import java.util.Locale;

/** Limits for the dedicated bill-image bridge. PDF/HTML routes are unchanged. */
final class InvoiceImageShare {
    static final int MAX_IMAGES = 50;
    static final long MAX_TOTAL_BYTES = 20L * 1024 * 1024;

    static void validateTotal(int count, long bytes) throws IOException {
        if (count < 1 || count > MAX_IMAGES) throw new IOException("Share up to 50 bill images at a time.");
        if (bytes < 0 || bytes > MAX_TOTAL_BYTES) throw new IOException("Bill images are too large. Share the pages individually.");
    }

    static void validateImage(String name, String mime, byte[] bytes) throws IOException {
        if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".jpg") || !"image/jpeg".equals(mime))
            throw new IOException("Invalid bill image type.");
        if (bytes == null || bytes.length < 4 || bytes.length > MAX_TOTAL_BYTES
            || (bytes[0] & 255) != 255 || (bytes[1] & 255) != 216
            || (bytes[2] & 255) != 255 || (bytes[bytes.length - 2] & 255) != 255
            || (bytes[bytes.length - 1] & 255) != 217)
            throw new IOException("Invalid bill image data.");
    }
}
