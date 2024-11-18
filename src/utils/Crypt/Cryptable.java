package utils.Crypt;

public interface Cryptable {
    public void generate() throws Exception;

    public void generate(int size) throws Exception;

    public void load() throws Exception;

    public void save() throws Exception;

    public String encrypt(String plainText) throws Exception;

    public String decrypt(String cipherText) throws Exception;
}
