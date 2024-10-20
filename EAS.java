import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EAS {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static String encrypt(String msg, String key) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            byte[] iv = new byte[cipher.getBlockSize()];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            byte[] encryptedMessage = cipher.doFinal(msg.getBytes("UTF-8"));

            // Combine IV and encrypted message
            byte[] combined = new byte[iv.length + encryptedMessage.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedMessage, 0, combined, iv.length, encryptedMessage.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting message", e);
        }
    }

    public static String decrypt(String encrypted, String key) {
        try {
            byte[] combined = Base64.getDecoder().decode(encrypted);
            byte[] iv = new byte[16]; // IV length for AES is 16 bytes
            System.arraycopy(combined, 0, iv, 0, iv.length);

            byte[] encryptedMessage = new byte[combined.length - iv.length];
            System.arraycopy(combined, iv.length, encryptedMessage, 0, encryptedMessage.length);

            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

            // Decrypt the message
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
            return new String(decryptedBytes, "UTF-8"); // Use UTF-8 encoding
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting message", e);
        }
    }

    public static String generateKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(32);
        
        for (int i = 0; i < 32; i++) {
            int randomIndex = random.nextInt(36);
            char randomChar;
            if (randomIndex < 26) {
                randomChar = (char) ('a' + randomIndex); // a-z
            } else {
                randomChar = (char) ('0' + (randomIndex - 26)); // 0-9
            }
            sb.append(randomChar);
        }
        
        return sb.toString();
    }
}
