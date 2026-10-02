package demo;
import jakarta.persistence.AttributeConverter;
public class StatusConverter implements AttributeConverter<Customer.Status,String> {
    public String convertToDatabaseColumn(Customer.Status s) { return s.name(); }
    public Customer.Status convertToEntityAttribute(String s) { return Customer.Status.valueOf(s); }
}
