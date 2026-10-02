package demo;
import jakarta.persistence.*;
// Bug 7: v2.0 flagged every @Convert. Expected v2.1: only 'card' (crypto converter, AES-ECB via "AES"), not 'status'.
@Entity public class Customer {
    @Convert(converter = CardEncryptor.class) private String card;
    @Convert(converter = StatusConverter.class) private Status status;
    enum Status { A, B }
}
