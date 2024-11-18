import utils.Crypt.AES;
import utils.Crypt.RSA;

import java.nio.file.Path;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;

public class Main {
    public static void main(String[] args) throws Exception {
        testAES();
//        testRSA();
    }

    private static void testAES() throws Exception {
        AES aes = new AES(Path.of("C:\\Users\\andre\\Desktop\\aes"));
//        aes.generate();
//        aes.generate(128);
//        aes.generate("123", "456");
//        aes.generate(128, "123", "456");
//        aes.save();
        aes.load();

        System.out.println("---java aes text---");
        String text = Files.readString(Path.of("C:\\Users\\andre\\Desktop\\aes\\text.txt"));System.out.println(text);

        String enc = aes.encrypt(text);System.out.println(enc);
        FileWriter encWriter = new FileWriter(Path.of("C:\\Users\\andre\\Desktop\\aes\\text_java_enc.txt").toFile());
        encWriter.write(enc);
        encWriter.close();

        String dec = aes.decrypt(enc);System.out.println(dec);

        System.out.println("=======================================");

        System.out.println("---php aes text---");
        String phpEnc = Files.readString(Path.of("C:\\Users\\andre\\Desktop\\aes\\text_php_enc.txt"));System.out.println(phpEnc);
        String phpDec = aes.decrypt(phpEnc);System.out.println(phpDec);

        System.out.println("=======================================");

        System.out.println("---java aes file---");
        Path file = Path.of("C:\\Users\\andre\\Desktop\\aes\\file.pdf");
        Path encryptedFile = Path.of("C:\\Users\\andre\\Desktop\\aes\\file_java_enc.pdf");
        Path decryptedFile = Path.of("C:\\Users\\andre\\Desktop\\aes\\file_java_dec.pdf");
        aes.encryptFile(file, encryptedFile);
        aes.decryptFile(encryptedFile, decryptedFile);System.out.println(decryptedFile);

        System.out.println("=======================================");

        System.out.println("---php aes file---");
        Path encryptedPhpFile = Path.of("C:\\Users\\andre\\Desktop\\aes\\file_php_enc.pdf");
        Path decryptedPhpFile = Path.of("C:\\Users\\andre\\Desktop\\aes\\file_php_dec.pdf");
        aes.decryptFile(encryptedPhpFile, decryptedPhpFile);System.out.println(decryptedPhpFile);

        System.out.println("=======================================");

        System.out.println("---java aes stream---");
        Path encryptedStream = Path.of("C:\\Users\\andre\\Desktop\\aes\\stream_java_enc.pdf");
        Path decryptedStream = Path.of("C:\\Users\\andre\\Desktop\\aes\\stream_java_dec.pdf");
        aes.encryptStream(file, encryptedStream);
        aes.decryptStream(encryptedStream, decryptedStream);System.out.println(decryptedStream);

        System.out.println("=======================================");

        System.out.println("---php aes stream---");
        Path encryptedPhpStream = Path.of("C:\\Users\\andre\\Desktop\\aes\\stream_php_enc.pdf");
        Path decryptedPhpStream = Path.of("C:\\Users\\andre\\Desktop\\aes\\stream_php_dec.pdf");
        aes.decryptStream(encryptedPhpStream, decryptedPhpStream);System.out.println(decryptedPhpStream);
    }

    private static void testRSA() throws Exception {
        RSA rsa = new RSA(Path.of("C:\\Users\\andre\\Desktop\\rsa"));
        rsa.load();
//        rsa.generate(4096);
//        rsa.save();

        System.out.println("---java rsa text---");
        String text = Files.readString(Path.of("C:\\Users\\andre\\Desktop\\rsa\\text.txt"));System.out.println(text);

        String enc = rsa.encrypt(text);System.out.println(enc);
        FileWriter encWriter = new FileWriter(Path.of("C:\\Users\\andre\\Desktop\\rsa\\text_java_enc.txt").toFile());
        encWriter.write(enc);
        encWriter.close();

        String dec = rsa.decrypt(enc);System.out.println(dec);

        System.out.println("=======================================");

        System.out.println("---php rsa text---");
        System.out.println(text);
        String phpText = Files.readString(Path.of("C:\\Users\\andre\\Desktop\\rsa\\text_php_enc.txt"));System.out.println(phpText);
        String phpDec = rsa.decrypt(phpText);System.out.println(phpDec);

        System.out.println("=======================================");

        System.out.println("---java rsa sign---");
        String signJava = rsa.sign(text);System.out.println(signJava);
        FileWriter signWriter = new FileWriter(Path.of("C:\\Users\\andre\\Desktop\\rsa\\sign_java.txt").toFile());
        signWriter.write(signJava);
        signWriter.close();
        System.out.println(rsa.verify(text, signJava));

        System.out.println("=======================================");

        System.out.println("---php rsa sign---");
        String signPhp = Files.readString(Path.of("C:\\Users\\andre\\Desktop\\rsa\\sign_java.txt"));System.out.println(signPhp);
        System.out.println(rsa.verify(text, signPhp));
    }
}
