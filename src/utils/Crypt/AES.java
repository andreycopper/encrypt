package utils.Crypt;

import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class AES extends Crypt implements Cryptable {
    private static final int BLOCK_SIZE = 65536;
    private static final int IV_SIZE = 16;

    private SecretKey key;

    public AES(Path directory) throws CryptException {
        setDirectory(directory);
        setAlgorithm("AES/CBC/PKCS5Padding");
    }

    public AES(Path directory, String algorithm) throws CryptException {
        setDirectory(directory);
        setAlgorithm(algorithm);
    }

    /**
     * Generate key
     * new AES(Path.of("keys_directory")).generate()
     */
    public void generate() throws Exception {
        generateKey(256);
    }

    /**
     * Generate key
     * new AES(Path.of("keys_directory")).generate(128)
     * @param size - key size (max 256)
     */
    public void generate(int size) throws Exception {
        generateKey(size);
    }

    /**
     * Generate key
     * new AES(Path.of("keys_directory")).generate("123", "456")
     * @param password - password
     * @param salt - salt
     */
    public void generate(String password, String salt) throws Exception {
        generateKeyWithPassword(256, password, salt);
    }

    /**
     * Generate key
     * new AES(Path.of("keys_directory")).generate(128, "123", "456")
     * @param size - key size (max 256)
     * @param password - password
     * @param salt - salt
     */
    public void generate(int size, String password, String salt) throws Exception {
        generateKeyWithPassword(size, password, salt);
    }

    /**
     * Generate key
     * @param size - key size (max 256)
     */
    private void generateKey(int size) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(Math.min(256, size));
        SecretKey key = generator.generateKey();
        setKey(key);
    }

    /**
     * Generate key with password
     * @param size - key size (max 256)
     * @param password - password
     * @param salt - salt
     */
    private void generateKeyWithPassword(int size, String password, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, Math.min(256, size));
        SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        setKey(key);
    }

    /**
     * Generate IV
     * @return - IV
     */
    private IvParameterSpec generateIv() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Load key
     * new AES(Path.of("keys_directory")).load()
     */
    public void load() throws Exception {
        setKey(getKey());
    }

    /**
     * Load key from PEM file
     * new AES(Path.of("keys_directory")).getKeyFromPEM()
     * @return - key
     */
    public SecretKey getKeyFromPEM() throws Exception {
        Path file = Path.of(directory + "\\key.pem");
        if (!Files.exists(file)) throw new Exception("Key not found");

//        try (PemReader pemReader = new PemReader(new FileReader(file.toFile()))) {
//            byte[] decoded = pemReader.readPemObject().getContent();
//            return new SecretKeySpec(decoded, 0, decoded.length, "AES");
//        }

        String key = Files.readString(file)
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\n", "");

        byte[] decoded = convertStringToBytes(key);
        return new SecretKeySpec(decoded, 0, decoded.length, "AES");
    }

    /**
     * Save key
     * new AES(Path.of("keys_directory")).save()
     * new AES(Path.of("keys_directory")).load().save()
     * new AES(Path.of("keys_directory")).generate().save()
     */
    public void save() {
        try (FileWriter writer = new FileWriter(directory + "\\key.pem")) {
            if (key != null) writer.write(convertBytesToString(key.getEncoded()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypt text
     * new AES(Path.of("keys_directory")).load().encrypt(text)
     * @param plainText - text to encrypt
     * @return - encrypted text
     */
    public String encrypt(String plainText) throws Exception {
        IvParameterSpec iv = generateIv();
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherBytes = cipher.doFinal(plainText.getBytes());

        byte[] encoded = new byte[cipherBytes.length + IV_SIZE];
        System.arraycopy(cipherBytes, 0, encoded, 0, cipherBytes.length);
        System.arraycopy(iv.getIV(), 0, encoded, cipherBytes.length, iv.getIV().length);
        return convertBytesToString(encoded);
    }

    /**
     * Decrypt text
     * new AES(Path.of("keys_directory")).load().decrypt(cipher)
     * @param cipherText - text to encrypt
     * @return - decrypted text
     */
    public String decrypt(String cipherText) throws Exception {
        byte[] cipherBytes = convertStringToBytes(cipherText);
        IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(cipherBytes, cipherBytes.length - 16, cipherBytes.length));
        byte[] encoded = Arrays.copyOfRange(cipherBytes, 0, cipherBytes.length - 16);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(encoded));
    }

    /**
     * Encrypt file
     * new AES(Path.of("keys_directory")).load().encryptFile(file, cipher)
     * @param inputFile - raw file
     * @param outputFile - encrypted file
     */
    public void encryptFile(Path inputFile, Path outputFile) {
        try(FileInputStream inputStream = new FileInputStream(inputFile.toFile());
            FileOutputStream outputStream = new FileOutputStream(outputFile.toFile())) {

            Cipher cipher = Cipher.getInstance(algorithm);
            IvParameterSpec iv = generateIv();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            outputStream.write(iv.getIV());

            byte[] buffer = new byte[BLOCK_SIZE];
            while (inputStream.available() > 0) {
                int bytesRead = inputStream.read(buffer);
                byte[] output = cipher.update(buffer, 0, bytesRead);
                outputStream.write(output);
            }

            byte[] outputBytes = cipher.doFinal();
            outputStream.write(outputBytes);
        } catch (Exception e) {
            System.out.println("Something went wrong : " + e);
        }
    }

    /**
     * Decrypt file
     * new AES(Path.of("keys_directory")).load().decryptFile(cipher, file)
     * @param inputFile - encrypted file
     * @param outputFile - decrypted file
     */
    public void decryptFile(Path inputFile, Path outputFile) {
        try(FileInputStream inputStream = new FileInputStream(inputFile.toFile());
            FileOutputStream outputStream = new FileOutputStream(outputFile.toFile())) {

            byte[] ivBytes = new byte[IV_SIZE];
            int ivBytesRead = inputStream.read(ivBytes);

            if (ivBytesRead == IV_SIZE) {
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, key, iv);

                byte[] buffer = new byte[BLOCK_SIZE];
                while (inputStream.available() > 0) {
                    int bytesRead = inputStream.read(buffer);
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    outputStream.write(output);
                }

                byte[] outputBytes = cipher.doFinal();
                outputStream.write(outputBytes);
            }
        } catch (Exception e) {
            System.out.println("Something went wrong : " + e);
        }
    }

    /**
     * Encrypt file partially
     * new AES(Path.of("keys_directory")).load().encryptStream(file, cipher)
     * @param inputFile - raw file
     * @param outputFile - encrypted file
     */
    public void encryptStream(Path inputFile, Path outputFile) {
        try(FileInputStream inputStream = new FileInputStream(inputFile.toFile());
            FileOutputStream outputStream = new FileOutputStream(outputFile.toFile())) {

            Cipher cipher = Cipher.getInstance(algorithm);
            IvParameterSpec iv = generateIv();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            outputStream.write(iv.getIV());

            byte[] buffer = new byte[BLOCK_SIZE];
            while (inputStream.available() > 0) {
                int bytesRead = inputStream.read(buffer);
                byte[] output = cipher.doFinal(buffer, 0, bytesRead);
                outputStream.write(output);
            }
        } catch (Exception e) {
            System.out.println("Something went wrong : " + e);
        }
    }

    /**
     * Decrypt file partially
     * new AES(Path.of("keys_directory")).load().decryptStream(cipher, file)
     * @param inputFile - encrypted file
     * @param outputFile - decrypted file
     */
    public void decryptStream(Path inputFile, Path outputFile) {
        try(FileInputStream inputStream = new FileInputStream(inputFile.toFile());
            FileOutputStream outputStream = new FileOutputStream(outputFile.toFile())) {

            byte[] ivBytes = new byte[IV_SIZE];
            int ivBytesRead = inputStream.read(ivBytes);

            if (ivBytesRead == IV_SIZE) {
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, key, iv);

                byte[] buffer = new byte[BLOCK_SIZE + IV_SIZE];
                while (inputStream.available() > 0) {
                    int bytesRead = inputStream.read(buffer);
                    byte[] output = cipher.doFinal(buffer, 0, bytesRead);
                    outputStream.write(output);
                }
            }
        } catch (Exception e) {
            System.out.println("Something went wrong : " + e);
        }
    }

    public SecretKey getKey() throws Exception {
        if (key == null) key = getKeyFromPEM();
        return key;
    }

    public void setKey(SecretKey key) {
        if (key != null && !Files.exists(Path.of(directory + "\\key.pem"))) save();
        this.key = key;
    }
}
