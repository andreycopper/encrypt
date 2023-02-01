
public class Main {
    public static void main(String[] args) throws Exception {
        try {
//            // генерация сертификатов без создания pem-файлов. шифрование и расшифровка фоазы.
//            HashMap<String, Key> rsa = RSA.generateCertificates();
//            PrivateKey privateKey = (PrivateKey) rsa.get("private");
//            PublicKey publicKey = (PublicKey) rsa.get("public");
//            // шифрование и расшифровка
//            String encryptedString2 = RSA.encrypt("Jopa prishla kozlu", publicKey);
//            System.out.println(encryptedString2);
//            String decryptedString2 = RSA.decrypt(encryptedString2, privateKey);
//            System.out.println(decryptedString2);


//            // генерация ssl сертификатов в pem-файлы
//            boolean isGenerated = RSA.generateOpenSSLCertificates(2, "UserId" + 2);
//            if (isGenerated) {
//                PrivateKey privateKey = RSA.getPrivateKeyFromPemFile(2);
//                PublicKey publicKey = RSA.getPublicKeyFromPemFile(2);
//                // шифрование и расшифровка
//                String encryptedString2 = RSA.encrypt("Кому-то скоро придет полный пиздец )))!!2-+", publicKey);
//                System.out.println(encryptedString2);
//                String decryptedString2 = RSA.decrypt(encryptedString2, privateKey);
//                System.out.println(decryptedString2);
//            }


            User user1 = new User(1);
            User user2 = new User(2);
            // шифрование и расшифровка
            String encryptedString1 = RSA.encrypt("Кому-то скоро придет полный пиздец )))!!2-+", user1.getPublicKey());
            System.out.println(encryptedString1);
            String decryptedString1 = RSA.decrypt(encryptedString1, user1.getPrivateKey());
            System.out.println(decryptedString1);
            // шифрование и расшифровка
            String encryptedString2 = RSA.encrypt("Кому-то скоро придет полный пиздец )))!!2-+", user2.getPublicKey());
            System.out.println(encryptedString2);
            String decryptedString2 = RSA.decrypt(encryptedString2, user2.getPrivateKey());
            System.out.println(decryptedString2);

            System.out.println("================================================");

            String messageFromUser1 = "u488X78I/v9Txn2D5q6egBM6koVSfnNti2DpquIcnUvmSyPFsNG4XHYNWhJZBwGcskrdetvWdnWjttmQrAuqzcH8oomsSBsdtLHeeKLAbrChPntdJxCxI26l9+bKMnCR9L1NBIZ1ng8BQ48Ray3DYKdtWFSJeb1yi2Z8VnAN4vCbrvvzjb6PGlHODYm4ELu0SAXO7bZUWDL4DV7Jwb7QjUgTu2t6U5gAZlb8aig4cTzTvrL7UybDbZPFwqkIuXbyxjn7f980M3yQzWjflwzm2jXNWkQleVQaCjsT1n3GXgHJYaqETUnYTScodG4XHImu5wUeTzqrqRIYzJH2MxHnfA==";
            String decryptedString3 = RSA.decrypt(messageFromUser1, user1.getPrivateKey());
            System.out.println(decryptedString3);

            String messageFromUser2 = "iO330LG6eO/j+XCkAQiYi4GZwqWMnMYbdQtcp+3q/BdT/Ox9yeVxIN//4UJtsAZqaPNDoIcOiLEKOnj1pmh0wYlGyTCHhFMbw+yfCyuFjedytoNGPS88N34iCgfw5rJ1VXtx3SAtHPIvFTDXFJkJYKRU8ShiH8NxII8EVykWvoiTL+KhukPNfFEz3dTCsstkbcHUICB8ELewwIvEQKQ/pj0HnLJWk9yc/OWyrwqWmdNoBjFphPOLGAzsR9eifaT2adgl0k5mIbHDHmSVPX5dS9zwSYZ76WNdo+kLSNkWivaYlcnsaVr3lI0/Ae4zqkwR9PGu8p4Isa10ZvDrcD5nWw==";
            String decryptedString4 = RSA.decrypt(messageFromUser2, user2.getPrivateKey());
            System.out.println(decryptedString4);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
