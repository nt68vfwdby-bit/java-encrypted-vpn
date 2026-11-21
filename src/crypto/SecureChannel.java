package crypto;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
public class SecureChannel {
    private static final String EC_CURVE = "secp256r1";
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH = 12;
    private final SecretKey sessionKey;
    private long sendSeq = 0; 
    private long recvSeq = 0; 
    public SecureChannel(SecretKey sessionKey) {
        this.sessionKey = sessionKey;
    }
    /**
     * Выполняет безопасное рукопожатие:
     * 1. Взаимная проверка пароля через HMAC-SHA256.
     * 2. Обмен эфемерными ключами ECDH.
     */
    public static SecureChannel performHandshake(
            DataInputStream in, DataOutputStream out, String preSharedSecret) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(EC_CURVE), new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] myPublicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] myHmac = computeHmac(myPublicKeyBytes, preSharedSecret);
        out.writeInt(myPublicKeyBytes.length);
        out.write(myPublicKeyBytes);
        out.writeInt(myHmac.length);
        out.write(myHmac);
        out.flush();
        int peerKeyLen = in.readInt();
        if (peerKeyLen <= 0 || peerKeyLen > 4096) {
            throw new SecurityException("Некорректная длина ключа при рукопожатии");
        }
        byte[] peerPublicKeyBytes = new byte[peerKeyLen];
        in.readFully(peerPublicKeyBytes);
        int peerHmacLen = in.readInt();
        byte[] peerHmac = new byte[peerHmacLen];
        in.readFully(peerHmac);
        byte[] expectedHmac = computeHmac(peerPublicKeyBytes, preSharedSecret);
        if (!MessageDigest.isEqual(peerHmac, expectedHmac)) {
            throw new SecurityException("Ошибка аутентификации: неверный пароль VPN");
        }
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey peerPublicKey = kf.generatePublic(new X509EncodedKeySpec(peerPublicKeyBytes));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(peerPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKeyBytes = sha256.digest(sharedSecret);
        Arrays.fill(sharedSecret, (byte) 0); 
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        Arrays.fill(aesKeyBytes, (byte) 0);
        return new SecureChannel(aesKey);
    }
    /**
     * Шифрует данные в AES-256-GCM с привязкой к номеру пакета и отправляет в поток.
     */
    public synchronized void sendEncrypted(DataOutputStream out, byte[] plainData) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        long currentSeq = ++sendSeq;
        byte[] seqBytes = ByteBuffer.allocate(Long.BYTES).putLong(currentSeq).array();
        cipher.updateAAD(seqBytes);
        byte[] cipherText = cipher.doFinal(plainData);
        out.writeLong(currentSeq);
        out.write(iv);
        out.writeInt(cipherText.length);
        out.write(cipherText);
        out.flush();
    }
    /**
     * Читает пакет, проверяет порядковый номер и расшифровывает AES-256-GCM.
     */
    public byte[] receiveEncrypted(DataInputStream in) throws Exception {
        long packetSeq = in.readLong();
        if (packetSeq != ++recvSeq) {
            throw new SecurityException("Обнаружена Replay-атака или нарушение порядка пакетов");
        }
        byte[] iv = new byte[IV_LENGTH];
        in.readFully(iv);
        int len = in.readInt();
        if (len <= 0 || len > 10 * 1024 * 1024) { 
            throw new IOException("Некорректный размер зашифрованного пакета");
        }
        byte[] cipherText = new byte[len];
        in.readFully(cipherText);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] seqBytes = ByteBuffer.allocate(Long.BYTES).putLong(packetSeq).array();
        cipher.updateAAD(seqBytes);
        return cipher.doFinal(cipherText);
    }
    private static byte[] computeHmac(byte[] data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }
}

