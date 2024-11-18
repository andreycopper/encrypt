package utils.Crypt;

import java.nio.file.Files;
import java.util.Base64;
import java.nio.file.Path;

abstract public class Crypt {
    protected Path directory;
    protected String algorithm; // AES/CBC/NoPadding, AES/CBC/PKCS5Padding, AES/ECB/NoPadding, AES/ECB/PKCS5Padding, AES/GCM/NoPadding, RSA/ECB/PKCS1Padding, RSA/ECB/NoPadding

    public static String convertBytesToString(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }

    public static byte[] convertStringToBytes(String key) {
        return Base64.getDecoder().decode(key);
    }

    public Path getDirectory() {
        return directory;
    }

    public void setDirectory(Path directory) throws CryptException {
        if (!Files.exists(directory)) throw new CryptException("Directory doesn't exist");
        this.directory = directory;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}
