package com.billmate.nativeapp;

import java.net.URI;

/** The native keyboard command is restricted to the live Billing page. */
final class BillingKeyboardScope {
    static boolean isBilling(String url) {
        if (!ShareUpload.isTrusted(url)) return false;
        try {
            String path = new URI(url).getPath();
            return "/billing".equals(path) || "/billing/".equals(path);
        } catch (Exception ignored) { return false; }
    }

    static boolean canShow(String url, boolean resumed, boolean focused) {
        return resumed && focused && isBilling(url);
    }
}
