package com.billmate.nativeapp;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.autofill.AutofillManager;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.webkit.JavaScriptReplyProxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** Per-use authenticated Android Keystore encryption; never stores passwords. */
final class BiometricVault {
    private final FragmentActivity activity;
    private final SharedPreferences preferences;
    private BiometricPrompt prompt;
    private String pendingAlias;

    BiometricVault(FragmentActivity activity) {
        this.activity = activity;
        preferences = activity.getSharedPreferences("billmate-biometric-v1", Context.MODE_PRIVATE);
    }

    void receive(String message, JavaScriptReplyProxy reply) {
        String id = "";
        try {
            if (message.length() > 8192) return;
            JSONObject data = new JSONObject(message);
            id = data.getString("id");
            if (!id.matches("[0-9]{1,12}")) return;
            String kind = data.getString("kind");
            if (!kind.equals("login") && !kind.equals("admin")) throw new Exception();
            String username = data.optString("username", "");
            if (username.length() > 100 || (kind.equals("admin") && username.isEmpty())) throw new Exception();
            String slot = slot(kind, username);
            String action = data.getString("action");
            if (action.equals("autofill_commit")) {
                AutofillManager autofill = activity.getSystemService(AutofillManager.class);
                if (autofill != null) autofill.commit();
                if (kind.equals("login") && !username.isEmpty()) preferences.edit().putString("login-username", username).apply();
                respond(reply, id, new JSONObject().put("success", true));
            } else if (action.equals("status")) {
                JSONObject saved = saved(slot);
                respond(reply, id, new JSONObject().put("setupVersion", 2).put("available", available()).put("saved", saved != null)
                    .put("username", saved == null ? (kind.equals("login") ? preferences.getString("login-username", "") : "") : saved.optString("username")));
            } else if (action.equals("forget")) {
                forget(slot);
                respond(reply, id, new JSONObject().put("success", true));
            } else if (action.equals("enroll") || action.equals("unlock")) {
                if (prompt != null) { error(reply, id, "Finish the current fingerprint request first."); return; }
                if (!available()) { error(reply, id, "Set up a supported fingerprint in phone settings, then use password login."); return; }
                boolean enrolling = action.equals("enroll");
                JSONObject saved = saved(slot);
                if (!enrolling && saved == null) { error(reply, id, "Use your password to enable fingerprint first."); return; }
                String token = enrolling ? data.getString("token") : "";
                if (enrolling && (username.isEmpty() || token.isEmpty() || token.length() > 4096)) throw new Exception();
                authenticate(reply, id, slot, kind, username, token, saved, enrolling);
            } else throw new Exception();
        } catch (Exception e) { error(reply, id, "Fingerprint could not start. Use password login."); }
    }

    private boolean available() {
        return BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            == BiometricManager.BIOMETRIC_SUCCESS;
    }

    private void authenticate(JavaScriptReplyProxy reply, String id, String slot, String kind,
                              String username, String token, JSONObject saved, boolean enrolling) {
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
            String alias;
            if (enrolling) {
                alias = "billmate-biometric-" + UUID.randomUUID();
                pendingAlias = alias;
                KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true);
                if (Build.VERSION.SDK_INT >= 30) spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
                else spec.setUserAuthenticationValidityDurationSeconds(-1);
                generator.init(spec.build()); generator.generateKey();
            } else alias = saved.getString("alias");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = (SecretKey) store.getKey(alias, null);
            if (enrolling) cipher.init(Cipher.ENCRYPT_MODE, key);
            else cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Base64.decode(saved.getString("iv"), Base64.NO_WRAP)));
            // Bind encrypted data to the account/access level as well as its key.
            // AAD is submitted only after biometric authorization succeeds.
            prompt = new BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    prompt = null;
                    try {
                        if (result.getCryptoObject() == null || result.getCryptoObject().getCipher() == null)
                            throw new java.security.GeneralSecurityException("Missing authenticated cipher");
                        Cipher unlocked = result.getCryptoObject().getCipher();
                        if (enrolling) {
                            byte[] iv = unlocked.getIV();
                            byte[] encrypted = VaultCipher.finish(unlocked, slot, token.getBytes(StandardCharsets.UTF_8));
                            JSONObject record = new JSONObject().put("alias", alias).put("username", username)
                                .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                                .put("ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP));
                            if (!preferences.edit().putString(slot, record.toString()).commit()) throw new Exception();
                            pendingAlias = null;
                            if (saved != null) deleteKey(saved.optString("alias"));
                            respond(reply, id, new JSONObject().put("success", true));
                        } else {
                            byte[] plain = VaultCipher.finish(unlocked, slot, Base64.decode(saved.getString("ciphertext"), Base64.NO_WRAP));
                            respond(reply, id, new JSONObject().put("token", new String(plain, StandardCharsets.UTF_8)));
                            java.util.Arrays.fill(plain, (byte) 0);
                        }
                    } catch (Exception e) {
                        if (enrolling) clearPendingKey(); else forget(slot);
                        error(reply, id, "Fingerprint " + (enrolling ? "setup" : "unlock") + " could not finish ("
                            + e.getClass().getSimpleName() + "). Retry from Fingerprint settings.");
                    }
                }
                @Override public void onAuthenticationError(int code, CharSequence text) {
                    prompt = null; clearPendingKey();
                    error(reply, id, "Fingerprint cancelled or unavailable. You can use your password.");
                }
            });
            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(enrolling ? "Enable BillMate fingerprint" : "Unlock BillMate" )
                .setSubtitle(username.isEmpty() ? saved.optString("username") : username)
                .setDescription(kind.equals("admin") ? "Verify admin access" : "Verify account login")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Use password").build();
            prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
        } catch (Exception e) {
            prompt = null; clearPendingKey();
            if (!enrolling) forget(slot);
            error(reply, id, "Phone security settings changed. Use your password to enable fingerprint again.");
        }
    }

    void cancel() { if (prompt != null) prompt.cancelAuthentication(); }
    private void clearPendingKey() { if (pendingAlias != null) { deleteKey(pendingAlias); pendingAlias = null; } }
    private JSONObject saved(String slot) {
        try { String value = preferences.getString(slot, null); return value == null ? null : new JSONObject(value); }
        catch (Exception e) { return null; }
    }
    private void forget(String slot) {
        JSONObject saved = saved(slot);
        preferences.edit().remove(slot).commit();
        if (saved != null) deleteKey(saved.optString("alias"));
    }
    private void deleteKey(String alias) {
        try { KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null); store.deleteEntry(alias); }
        catch (Exception ignored) { }
    }
    private String slot(String kind, String username) throws Exception {
        if (kind.equals("login")) return "login";
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(username.getBytes(StandardCharsets.UTF_8));
        return "admin-" + Base64.encodeToString(hash, Base64.NO_WRAP);
    }
    private void respond(JavaScriptReplyProxy reply, String id, JSONObject data) {
        try { data.put("id", id); reply.postMessage(data.toString()); } catch (Exception ignored) { }
    }
    private void error(JavaScriptReplyProxy reply, String id, String message) {
        try { respond(reply, id, new JSONObject().put("error", message)); } catch (Exception ignored) { }
    }
}
