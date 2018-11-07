import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHATest {
    public static void main (String[] args) throws NoSuchAlgorithmException, IOException {
        String plainText;
        BufferedReader br=new BufferedReader((new InputStreamReader(System.in)));
        System.out.println("Enter Plain Text:");
        plainText=br.readLine();
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        byte[] hasedValue=md.digest(plainText.getBytes(StandardCharsets.UTF_8));
        System.out.println("Plain Text:"+plainText);
        System.out.println("Hashed Value:");
        StringBuilder sb = new StringBuilder();
        for (byte b : hasedValue) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());

    }
}