package com.billmate.nativeapp;

import org.junit.Test;
import static org.junit.Assert.*;

public class BillingKeyboardScopeTest {
    private static final String ORIGIN = "https://billmate-med.vercel.app";

    @Test public void acceptsOnlyLiveBillingWithWindowFocus() {
        assertTrue(BillingKeyboardScope.canShow(ORIGIN + "/billing", true, true));
        assertTrue(BillingKeyboardScope.canShow(ORIGIN + "/billing/?invoice=12", true, true));
        assertFalse(BillingKeyboardScope.canShow(ORIGIN + "/billing", false, true));
        assertFalse(BillingKeyboardScope.canShow(ORIGIN + "/billing", true, false));
    }

    @Test public void rejectsEveryOtherPage() {
        for (String path : new String[]{"/", "/items", "/demand-search", "/payments", "/purchase", "/customers", "/admin/sales", "/billing/other"}) {
            assertFalse(path, BillingKeyboardScope.canShow(ORIGIN + path, true, true));
        }
    }

    @Test public void rejectsUntrustedOriginsAndMalformedUrls() {
        for (String url : new String[]{null, "", "not a URL", "http://billmate-med.vercel.app/billing",
            "https://example.com/billing", "https://billmate-med.vercel.app.evil.example/billing",
            "https://evil@billmate-med.vercel.app/billing", "https://billmate-med.vercel.app:444/billing"}) {
            assertFalse(BillingKeyboardScope.canShow(url, true, true));
        }
    }
}
