package com.billmate.nativeapp;

import org.junit.Test;
import static org.junit.Assert.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;

public class VaultCipherTest {
    @Test public void roundTripAndRejectOtherAccountOrAccess() throws Exception {
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = encrypt.getIV();
        byte[] plain = "device-token".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = VaultCipher.finish(encrypt, "admin-first", plain);
        Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        assertArrayEquals(plain, VaultCipher.finish(decrypt, "admin-first", encrypted));
        for (String slot : new String[]{"login", "admin-second"}) {
            decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            try { VaultCipher.finish(decrypt, slot, encrypted); fail("Wrong access must fail"); }
            catch (javax.crypto.AEADBadTagException expected) { }
        }
    }
}
