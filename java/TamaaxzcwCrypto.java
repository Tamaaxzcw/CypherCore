// Author: Tamaaxzcw
// GitHub: https://github.com/Tamaaxzcw

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class TamaaxzcwCrypto {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_SIZE_BYTE = 12;
    private static final int SALT_SIZE_BYTE = 16;
    private static final String KEY_DERIVATION_ALGO = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 250000;
    private static final int KEY_LENGTH_BIT = 256;

    public static String encrypt(String plainText, String secret) throws Exception {
        byte[] salt = new byte[SALT_SIZE_BYTE];
        new SecureRandom().nextBytes(salt);

        byte[] iv = new byte[IV_SIZE_BYTE];
        new SecureRandom().nextBytes(iv);
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGO);
        KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, ITERATIONS, KEY_LENGTH_BIT);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
        // Combine salt, iv, and ciphertext
        byte[] encryptedPayload = ByteBuffer.allocate(salt.length + iv.length + cipherText.length)
            .put(salt)
            .put(iv)
            .put(cipherText)
            .array();

        return Base64.getEncoder().encodeToString(encryptedPayload);
    }

    public static String decrypt(String encryptedPayload, String secret) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedPayload);
        ByteBuffer bb = ByteBuffer.wrap(decoded);

        byte[] salt = new byte[SALT_SIZE_BYTE];
        bb.get(salt);
        byte[] iv = new byte[IV_SIZE_BYTE];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGO);
        KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, ITERATIONS, KEY_LENGTH_BIT);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }
  }
