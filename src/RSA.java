import javax.crypto.Cipher;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

public class RSA {
    protected static final String X509 = "X.509";
    protected static final String PKCS1 = "PKCS#1";
    protected static final String PKCS8 = "PKCS#8";

    /**
     * Генерация пары ключей. приватный в формате PKCS8
     * @return - возвращает массив с ключами private и public
     * @throws NoSuchAlgorithmException
     */
    protected static HashMap<String, Key> generateCertificates() throws NoSuchAlgorithmException {
        HashMap<String, Key> keys = new HashMap<>();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        keys.put("private", keyPair.getPrivate());
        keys.put("public", keyPair.getPublic());

        return keys;
    }

    protected static boolean generateOpenSSLCertificates(int userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {
        return generateOpenSSLCertificates(userId, "");
    }

    /**
     * Генерирует публичный и приватные ключи (PKCS#1 и PKCS#8) в pem-файл
     * Получает ключи возвращает в виде массива
     * @param userId - id пользователя
     * @param passphrase - кодовая фраза
     * @return - возвращает массив с ключами private и public
     * @throws IOException
     * @throws InterruptedException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    protected static boolean generateOpenSSLCertificates(int userId, String passphrase) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Path.of(Paths.get("").toAbsolutePath() + File.separator + "certificates" + File.separator + userId);
        if (!Files.exists(path)) new File(path.toString()).mkdirs();
        // создание ключей внешней командой openssl
        Runtime.getRuntime().exec("openssl genpkey -algorithm RSA -out " + path + File.separator + "private.pem -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -pass pass:" + passphrase);
        Thread.sleep(1000);
        Runtime.getRuntime().exec("openssl pkcs8 -topk8 -nocrypt -in " + path + File.separator + "private.pem -passin pass:" + passphrase + " -out " + path + File.separator + "private_pcks8.pem -passout pass:" + passphrase);
        Thread.sleep(1000);
        Runtime.getRuntime().exec("openssl rsa -in " + path + File.separator + "private.pem -passin pass:" + passphrase + " -pubout -out " + path + File.separator + "public.pem");
        Thread.sleep(1000);

        Path publicKey = Path.of(path + File.separator + "public.pem");
        Path privateKey = Path.of(path + File.separator + "private.pem");
        Path privateKeyPCKS8 = Path.of(path + File.separator + "private_pcks8.pem");

        return Files.exists(publicKey) && Files.exists(privateKey) && Files.exists(privateKeyPCKS8);
    }

    protected static RSAPublicKey getPublicKeyFromPemFile(int userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Path.of(Paths.get("").toAbsolutePath() + File.separator + "certificates" + File.separator + userId + File.separator + "public.pem");
        if (Files.exists(path)) {
            String publickey = Files.readString(path);
            return getPublicKey(publickey);
        }
        return null;
    }

    protected static RSAPrivateKey getPrivateKeyFromPemFile(int userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Path.of(Paths.get("").toAbsolutePath() + File.separator + "certificates" + File.separator + userId + File.separator + "private_pcks8.pem");
        if (Files.exists(path)) {
            String privatekey = Files.readString(path);
            return getPrivateKey(privatekey);
        }
        return null;
    }

    /**
     * Возвращает публичный ключ из PEM - файла ключа
     * @param publicKey - публичный ключ в формате PEM
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    protected static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = publicKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\n", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        //PemReader reader = new PemReader(new StringReader(publicKey));
        //byte[] encoded = reader.readPemObject().getContent();

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    /**
     * Возвращает приватный ключ из PEM - файла ключа
     * @param privateKey - приватный ключ в формате PEM
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    protected static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = privateKey
            .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\n", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        //PemReader reader = new PemReader(new StringReader(privateKey));
        //byte[] encoded = reader.readPemObject().getContent();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    /**
     * Шифрует сообщение
     * @param rawText - текст для шифрования
     * @param key - публичный ключ в PEM формате (из файла ключа)
     * @return
     * @throws Exception
     */
    public static String encrypt(String rawText, String key) throws Exception {
        return encrypt(rawText, RSA.getPublicKey(key));
    }

    /**
     * Шифрует сообщение
     * @param rawText - текст для шифрования
     * @param publicKey - публичный ключ
     * @return
     * @throws GeneralSecurityException
     */
    public static String encrypt(String rawText, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(rawText.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Расшифровывает сообщение
     * @param cipherText - шифрованный текст
     * @param key - приватный ключ в PEM формате (из файла ключа)
     * @return
     * @throws Exception
     */
    public static String decrypt(String cipherText, String key) throws Exception {
        return decrypt(cipherText, RSA.getPrivateKey(key));
    }

    /**
     * Расшифровывает сообщение
     * @param cipherText - шифрованный текст
     * @param privateKey - приватный ключ
     * @return
     * @throws GeneralSecurityException
     */
    public static String decrypt(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText.replace("\n", ""))), StandardCharsets.UTF_8);
    }
}
