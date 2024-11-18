package utils.Crypt;

import java.io.*;
import java.security.*;
import java.nio.file.Path;
import java.nio.file.Files;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.security.spec.InvalidKeySpecException;

public class RSA extends Crypt implements Cryptable {
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public RSA(Path directory) throws Exception {
        if (!Files.exists(directory)) throw new Exception("Directory doesn't exist");
        this.directory = directory;
        this.algorithm = "RSA/ECB/PKCS1Padding";
    }

    public RSA(Path directory, String algorithm) throws Exception {
        if (!Files.exists(directory)) throw new Exception("Directory doesn't exist");
        this.directory = directory;
        this.algorithm = algorithm;
    }

    /**
     * Generate keys
     * new RSA(Path.of("keys_directory")).generate()
     */
    public void generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        setPrivateKey((RSAPrivateKey) pair.getPrivate());
        setPublicKey((RSAPublicKey) pair.getPublic());
    }

    /**
     * Generate keys
     * new RSA(Path.of("keys_directory")).generate(4096)
     * @param size - key size
     */
    public void generate(int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(size);
        KeyPair pair = generator.generateKeyPair();
        setPrivateKey((RSAPrivateKey) pair.getPrivate());
        setPublicKey((RSAPublicKey) pair.getPublic());
    }

    /**
     * Load keys
     * new RSA(Path.of("keys_directory")).load()
     */
    public void load() throws Exception {
        if (!Files.exists(Path.of(directory + "\\private.pem")) ||
            !Files.exists(Path.of(directory + "\\public.pem"))) throw new Exception("Keys not found");

        setPrivateKey(getPrivateKey());
        setPublicKey(getPublicKey());
    }

    /**
     * Load private key from PEM file
     * @return - private key
     */
    public RSAPrivateKey getPrivateKeyFromPEM() throws Exception {
        Path file = Path.of(directory + "\\private.pem");
        if (!Files.exists(file)) throw new Exception("Private file doesn't exist");

//        try (PemReader pemReader = new PemReader(new FileReader(file.toFile()))) {
//            return convertToPrivateKey(pemReader.readPemObject().getContent());
//        }

        String privateKey = Files.readString(file)
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\n", "");

        return convertToPrivateKey(convertStringToBytes(privateKey));
    }

    /**
     * Load public key from PEM file
     * @return - public key
     */
    public RSAPublicKey getPublicKeyFromPEM() throws Exception {
        Path file = Path.of(directory + "\\public.pem");
        if (!Files.exists(file)) throw new Exception("Public file doesn't exist");

//        try (PemReader pemReader = new PemReader(new FileReader(file.toFile()))) {
//            return convertToPublicKey(pemReader.readPemObject().getContent());
//        }

        String publicKey = Files.readString(file)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replace("\n", "");

        return convertToPublicKey(convertStringToBytes(publicKey));
    }

    /**
     * Save keys
     * new RSA(Path.of("keys_directory")).save()
     * new RSA(Path.of("keys_directory")).load().save()
     * new RSA(Path.of("keys_directory")).generate().save()
     */
    public void save() throws Exception {
        savePrivateKey();
        savePublicKey();
    }

    /**
     * Save private key
     * new RSA(Path.of("keys_directory")).savePrivateKey()
     */
    public void savePrivateKey() throws Exception {
        try (PemWriter privateWriter = new PemWriter(new FileWriter(directory + "\\private.pem"))) {
            if (privateKey != null) privateWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

//        try (FileWriter privateWriter = new FileWriter(directory + "\\private.pem")) {
//            privateWriter.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
    }

    /**
     * Save public key
     * new RSA(Path.of("keys_directory")).savePublicKey()
     */
    public void savePublicKey() throws Exception {
        try (PemWriter publicWriter = new PemWriter(new FileWriter(directory + "\\public.pem"))) {
            if (publicKey != null) publicWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

//        try (FileWriter publicWriter = new FileWriter(directory + "\\public.pem")) {
//            publicWriter.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
    }

    /**
     * Encrypt text
     * new RSA(Path.of("keys_directory")).load().encrypt(text)
     * @param plainText - text to encrypt
     * @return - encrypted text
     */
    public String encrypt(String plainText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return convertBytesToString(cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Encrypt text
     * new RSA(Path.of("keys_directory")).load().encrypt(text, key)
     * @param plainText - text to encrypt
     * @param key - ключ
     * @return - encrypted text
     */
    public String encrypt(String plainText, Key key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return convertBytesToString(cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Encrypt text
     * new RSA(Path.of("keys_directory")).load().encryptByPrivateKey(text)
     * @param plainText - text to encrypt
     * @return - encrypted text
     */
    public String encryptByPrivateKey(String plainText) throws Exception {
        return encrypt(plainText, getPrivateKey());
    }

    /**
     * Decrypt text
     * new RSA(Path.of("keys_directory")).load().decrypt(cipher)
     * @param cipherText - text to decrypt
     * @return - decrypted text
     */
    public String decrypt(String cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(convertStringToBytes(cipherText)), StandardCharsets.UTF_8);
    }

    /**
     * Decrypt text
     * new RSA(Path.of("keys_directory")).load().decrypt(cipher, key)
     * @param cipherText - text to decrypt
     * @param key - ключ
     * @return - decrypted text
     */
    public String decrypt(String cipherText, Key key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(convertStringToBytes(cipherText)), StandardCharsets.UTF_8);
    }

    /**
     * Decrypt text
     * new RSA(Path.of("keys_directory")).load().decryptByPublicKey(cipher)
     * @param cipherText - text to decrypt
     * @return - decrypted text
     */
    public String decryptByPublicKey(String cipherText) throws Exception {
        return decrypt(cipherText, getPublicKey());
    }

    /**
     * Sign text
     * new RSA(Path.of("keys_directory")).load().sign(text)
     * @param text - text to sign
     * @return - signature string
     */
    public String sign(String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA"); // SHA1withRSA, SHA224withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA, SHA512/224withRSA, SHA512/256withRSA, RSASSA-PSS, NONEwithRSA
        signature.initSign(privateKey, new SecureRandom());
        signature.update(text.getBytes(StandardCharsets.UTF_8));
        return convertBytesToString(signature.sign());
    }

    /**
     * Verify signed text
     * new RSA(Path.of("keys_directory")).load().verify(text, signature)
     * @param text - text to verify
     * @param signature - text sign
     * @return - verifying result
     */
    public boolean verify(String text, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(text.getBytes(StandardCharsets.UTF_8));
        return sign.verify(convertStringToBytes(signature));
    }

    /**
     * Convert bytes to rsa private key
     * @param decoded - key bytes
     * @return - rsa private key
     */
    public RSAPrivateKey convertToPrivateKey(byte[] decoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
    }

    /**
     * Convert bytes to rsa public key
     * @param decoded - key bytes
     * @return - rsa public key
     */
    public RSAPublicKey convertToPublicKey(byte[] decoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decoded);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    }

    public RSAPrivateKey getPrivateKey() throws Exception {
        if (privateKey == null && Files.exists(Path.of(directory + "\\private.pem"))) setPrivateKey(getPrivateKeyFromPEM());
        return privateKey;
    }

    public void setPrivateKey(RSAPrivateKey privateKey) throws Exception {
        if (Files.exists(directory) && !Files.exists(Path.of(directory + "\\private.pem"))) savePrivateKey();
        this.privateKey = privateKey;
    }

    public RSAPublicKey getPublicKey() throws Exception {
        if (publicKey == null && Files.exists(Path.of(directory + "\\public.pem"))) setPublicKey(getPublicKeyFromPEM());
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) throws Exception {
        if (Files.exists(directory) && !Files.exists(Path.of(directory + "\\public.pem"))) savePublicKey();
        this.publicKey = publicKey;
    }
}
