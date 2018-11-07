/*
Tasks 2: Programming (12 marks)
Alice and Bob intend to do message exchange. They will use the following method to establish a
secure channel and exchange messages then.
• Alice and Bob uses STS protocol to establish a session key.
• Once session key is created, they use 3-DES encryption to protect message confidentiality.
• To enhance the security, they also apply the Counter Mode with 3-DES encryption for each
message.
Your task: Please implement the above mechanism using C++ or Java under the following requirement.
• Any public key encryption or digital signature scheme needed in this method will be based on
RSA.
• Any symmetric key encryption applied in this method will be 3-DES.
• Any hash function used in this method will be SHA-256. You can use its implementation from
external libraries.
• Implement STS protocol. (3 marks)
• Implement RSA encryption and signature, because you cannot use it directly from external
libraries. (2 marks)
• Implement 3-DES encryption. You can use DES implementation from any cryptographic libraries. (2 marks)
• Assume that Alice and Bob know each other’s public key at the beginning.
• Implement the Counter (CTR) Mode. (2 marks)
• Show that Alice and Bob can send/receive messages by using 3-DES with CTR mode after the
secure session established. Assume that each message will be in 64 bytes. (3 marks)
• You can use socket programming or simulate message sending/receiving by using function calls.
• You MUST use BigIntegers (Java) or NTL (C++) to handle large number computation. Note
that, the RSA key size must be at least 1024-bit.
Notes
• Submit the source code and provide a screen shot in your report to show the program execution.
3• Provide instructions to show how the program will be compiled and executed.
• Provide name (and installation instructions if needed) of external cryptographic libraries used
for the implementation. In this case, you should specify what method/package was used for the
assignment.
• Uncompilable or unexecutable program may receive zero mark
 */
import java.util.Scanner;
import java.math.BigInteger;
import java.lang.Math;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;

public class Tasks2
{
    public static void main(String[] args) throws Exception
    {
       Scanner sc = new Scanner(System.in);
       System.out.println("\n");

        int newP = generatePrime();
        int newG = generateElement(newP);

        //generates, alice and bobs keypairs
        KeyPair AliceKey = generateKeyPair();
        KeyPair BobKey = generateKeyPair();

        System.out.println("An asymmetric signature keypair for each party has been generated\n");
        System.out.println("Safe prime and Generator has been created as well\n");

//        System.out.println("prime " + newP+"\n");
//        System.out.println("generator " + newG+"\n");
//
//        System.out.println("Alice public: "+AliceKey.getPublic() +"\n Bob public: "+BobKey.getPublic()+"\n");
//        System.out.println("Alice private: "+AliceKey.getPrivate() +"\n Bob private: "+BobKey.getPrivate()+"\n");

        System.out.println("Alice generates a random number x: ");
        int x = sc.nextInt();
        System.out.println("then send g^x to Bob\n");

        System.out.println("Bob generates a random number y: ");
        int y = sc.nextInt();

        //K=(g^x)^y
        int BobK = computeExp(computeExp(newG,x),y);
        System.out.println("Bob computates the shared key K=(g^x)^y: "+BobK);

        String xString = Integer.toString(computeExp(newG,x));
        String yString = Integer.toString(computeExp(newG,y));

        //concatenate binery or string?
        String gygx = yString + xString;
        System.out.println("Bob concatenates g^y g^x\n");

        //signs the concatenated string with his private key
        String sig1 = sign(gygx, BobKey.getPrivate());
        System.out.println("signs the concatenated string with his private key");

        //encrypts the signature with K
        System.out.println("encrypts the signature with K");
        String sig2 = encrypt(sig1,BobKey.getPublic());

        //sends cipher text with his g^y to Alice

        //Alice then computes K=(g^y)^x
        int AliceK = computeExp(computeExp(newG,y),x);
        System.out.println(AliceK + " then "+ BobKey);




    }
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception 
    {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }
    public static String sign(String plainText, PrivateKey privateKey) throws Exception 
    {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static KeyPair generateKeyPair() throws Exception 
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024, new SecureRandom());
        KeyPair pair = gen.generateKeyPair();

        return pair;
    }
    public static int computeExp(int g, int num)
    {
        double expNum = Math.pow(g,num);
        int newNum = (int) expNum;
        return newNum;
    }
    //Bob concatenates the exponentials (gy, gx) (order is important), signs them using his asymmetric (private) key B,
    // and then encrypts the signature with K. He sends the ciphertext along with his own exponential gy to Alice.
//    public static String verification(int y, int x)
//    {
//        String xString = Integer.toString(x);
//        String yString = Integer.toString(y);
//        String conString = "";
//
//        //concatenate the g^y and g^x
//        conString = yString + xString;
//
//        sign(conString,????);
//
//
//    }

    public static int generateElement(int prime)
    {
        int g = prime+1;
        while(true)
        {
            int bitLength= 512;
            SecureRandom rnd2=new SecureRandom();
            g=BigInteger.probablePrime(bitLength, rnd2).intValue();
            if (prime > g && g > 0)
            {
				return g;
            }
        }
    }

    public static int generatePrime()
    {
		int safeP = 16;
		/*7 is a known prime that doesn't generate a safe prime when*/
		/*You plug it in, creates 15, so the while loops as long as a safe prime is not found*/
		while(safeP != 7)
		{
            /*generates random prime numbers*/
            SecureRandom rnd1=new SecureRandom();
            int bits = 1024;
			safeP =BigInteger.probablePrime(bits, rnd1).intValue();
			
			/*Creates a safe prime*/
			safeP = 2*safeP+1;
			
			/*Checks if it is still a prime after calculations also has to be positive*/
            if (isPrime(safeP) && safeP>0)
            {
				return safeP;
            }
        }
        //false news
        return -1;

    }

    public static boolean isPrime(int number) 
    { 
        //if 2 or 3 return true
        if(number == 2 || number == 3) 
        { 
            return true; 
        } 
        //if even number
        if(number % 2 == 0) 
        { 
            return false; 
        } 

        int sqrt = (int) Math.sqrt(number) + 1; 

        for(int i = 3; i < sqrt; i += 2) 
        { 
            if (number % i == 0) 
            { 
                return false; 
            } 
        } 
        //can't find so is true
        return true; 
    }


    
}
