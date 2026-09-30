package com.billmate.nativeapp;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;

/** Called only with the cipher returned by successful biometric authentication. */
final class VaultCipher {
    private VaultCipher() { }
    static byte[] finish(Cipher authenticatedCipher, String slot, byte[] data)
            throws GeneralSecurityException {
        authenticatedCipher.updateAAD(slot.getBytes(StandardCharsets.UTF_8));
        return authenticatedCipher.doFinal(data);
    }
}
