package demo;
import jakarta.persistence.AttributeConverter;
public class CardEncryptor implements AttributeConverter<String,String> {
    public String convertToDatabaseColumn(String s) { try { javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES"); return s; } catch (Exception e) { throw new RuntimeException(e); } }
    public String convertToEntityAttribute(String s) { return s; }
}
