/**
 * *
 *  * Tasks2.java – Assignment3
 *   * @author: Juyong Kim
 *    * @student Number: c3244203
 *     * @version: 08/11/2018
 *      * Description: Task2
 *       */
import java.math.*;
import java.security.*;
import javax.crypto.*;
import java.util.Scanner;
import java.io.InputStream;
import java.util.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Tasks2
{
    public static void main(String[] args) throws Exception
    {
       Scanner sc = new Scanner(System.in);
       System.out.println("\n");

        BigInteger newP = generatePrime();
        BigInteger newQ = generatePrime();
        BigInteger newG = generatePrime();
        BigInteger n = newP.multiply(newQ);

        //m=(p-1)(q-1)
        BigInteger m = (newP.subtract(BigInteger.ONE)).multiply(newQ.subtract(BigInteger.ONE));
        BigInteger e = generateE(m);
        BigInteger d = generateD(e,n);

        //create private keys
        BigInteger BobPrivate=generatePrivateKey(newP);
        BigInteger AlicePrivate=generatePrivateKey(newP);
        System.out.println("\nBob generates private key "+BobPrivate);
        System.out.println("\nAlice generates private key "+AlicePrivate);

        //create public keys
        BigInteger BobPublic=generatePublicKey(newG,BobPrivate,newP);
        BigInteger AlicePublic=generatePublicKey(newG,AlicePrivate,newP);
        System.out.println("\nBob generates public key "+BobPublic);
        System.out.println("\nAlice generates public key "+AlicePublic);

        //Alice's x value
        int x = 5;

        //Alice generate g^x
        BigInteger gx = newG.pow(x);

        //Bob's y value
        int y = 4;

        //Bob generates g^y
        BigInteger gy = newG.pow(y);

        //Bob generates the shared key K=(g^x)^y
        BigInteger bobK = gx.pow(y);

        //Bob concatenates g^y and g^x
        String s1 = gx.toString();
        String s2 = gy.toString();
        String s3 = s2 + s1;

        //Bob signs the msg g^y and g^x
        String bobMsg = sign(s3,d,n);

        //Bob sends the signed msg and his g^y to alice

        //Alice decrypts the signed msg and verifies it
        System.out.println("the msg is "+ verify(s3, bobMsg ,e ,n));

        //Alice generates the shared key K=(g^x)^y
        BigInteger aliceK = gy.pow(x);

        //Alice concatenates g^x and g^y
        String f1 = gx.toString();
        String f2 = gy.toString();
        String f3 = f1 + f2;

        //Bob signs the msg g^y and g^x
        String aliceMsg = sign(f3,d,n);

        //Alice sends the signed msg to Bob

        //Bob decrypts and verifies Alice's signature using her asymmetric public key.
        System.out.println("the msg is "+ verify(f3, aliceMsg ,e ,n));

        //Alice and Bob are now mutually authenticated and have a shared secret. This secret, K

        //Testing 3DES

        String text = "this message is unreadable";

        byte[] codedText = new TripleDESTest().encrypt(text);
        String decodedText = new TripleDESTest().decrypt(codedText);

        System.out.println("Original text: "+text);
        System.out.println("Encrypted text: "+codedText); 
        System.out.println("Decrypted text: "+decodedText); 

    }
    public static byte [] hash(String input) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(input.getBytes());
        byte [] b = md.digest();
        StringBuffer sb = new StringBuffer();

        for(byte b1 : b)
        {
            sb.append(Integer.toHexString(b1 & 0xff).toString());
        }
        return b;
    }
    public byte[] encrypt(String message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest("HG58YZ3CR9"
                .getBytes("utf-8"));
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] plainTextBytes = message.getBytes("utf-8");
        final byte[] cipherText = cipher.doFinal(plainTextBytes);
        // final String encodedCipherText = new sun.misc.BASE64Encoder()
        // .encode(cipherText);

        return cipherText;
    }

    public String decrypt(byte[] message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest("HG58YZ3CR9"
                .getBytes("utf-8"));
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);

        // final byte[] encData = new
        // sun.misc.BASE64Decoder().decodeBuffer(message);
        final byte[] plainText = decipher.doFinal(message);

        return new String(plainText, "UTF-8");
    }
    //Y = (X^e)modn
    public static String encrypt(String plaintext, BigInteger e, BigInteger n)
    {
        BigInteger temp;
        BigInteger x = new BigInteger(plaintext);

        temp = x.modPow(e,n);

        return temp.toString();
    }
    //X = (Y^d)modn
    public static String decrypt(String ciphertext, BigInteger e, BigInteger n)
    {
        BigInteger temp;
        BigInteger x = new BigInteger(ciphertext);

        temp = x.modPow(e,n);

        return temp.toString();
    }
    //S=h(m)^d mod n
    public static String sign(String value, BigInteger d, BigInteger n) throws NoSuchAlgorithmException
    {
        byte[] hash1 = hash(value);
        String sig;
        BigInteger m = new BigInteger(hash1);
        BigInteger com;
        com = m.modPow(d,n);
        sig = com.toString();
        return sig;
    }
    //h(m)=S^e mod n
    public static Boolean verify(String m, String msg, BigInteger e, BigInteger n) throws NoSuchAlgorithmException
    {
        Boolean verification = false;
        BigInteger hm = new BigInteger(hash(m));
        System.out.println("hm "+ hm.toString());
        BigInteger newMsg = new BigInteger(msg);
        BigInteger value = newMsg.modPow(e, n);
        Boolean verifcation = true;
        System.out.println("value "+ value.toString());
        if(hm.compareTo(value)==0)
        {
            verification = true;
            return verification;
        }

        return verifcation;
    }

    public static BigInteger generateD(BigInteger e,BigInteger n)
    {
        BigInteger d;

        d = e.modInverse(n);

        return d;
    }
    public static BigInteger generateE(BigInteger m)
    {
        BigInteger n = m.subtract(BigInteger.ONE);
        BigInteger e;
        int bits= 1024;
        SecureRandom rnd1=new SecureRandom();
        e = new BigInteger(bits, rnd1);

        while(true)
        {

            int bitLength= 1024;
            SecureRandom rnd2=new SecureRandom();
            e = new BigInteger(bitLength, rnd2);

            if(m.gcd(e).compareTo(BigInteger.ONE)==0 && e.compareTo(n)==-1 && e.compareTo(BigInteger.ONE)==1)
            {
                return e;
            }
        }
        
    }
    public static BigInteger computeExp(BigInteger g, int num)
    {
        BigInteger newNum = g.pow(num);
        return newNum;
    }

    public static BigInteger generatePrime()
    {
        BigInteger p;
        int bitLength= 1024;
        SecureRandom rnd1=new SecureRandom();
        p=BigInteger.probablePrime(bitLength, rnd1);
        return p;
    }
    public static BigInteger generatePrivateKey(BigInteger num)
    {
        BigInteger num2;
        while(true)
        {
            int bitLength= 1024;
            SecureRandom rnd2=new SecureRandom();
            num2 = new BigInteger(bitLength, rnd2);

            if(num2.compareTo(num)==-1 && num2.compareTo(BigInteger.ONE)==1)
            {
                return num2;
            }
        }
    }
    public static BigInteger generatePublicKey(BigInteger g, BigInteger privateKey, BigInteger p)
    {
        BigInteger num;
        num = g.modPow(privateKey,p);
        return num;
    }

//    //generates key pair
//    public static KeyPair generateKeyPair() throws Exception {
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//        generator.initialize(1024, new SecureRandom());
//        KeyPair pair = generator.generateKeyPair();
//
//        return pair;
//    }
//    public static String sign(String plainText, PrivateKey privateKey) throws Exception 
//    {
//        Signature privateSignature = Signature.getInstance("SHA256withRSA");
//        privateSignature.initSign(privateKey);
//        privateSignature.update(plainText.getBytes(UTF_8));
//
//        byte[] signature = privateSignature.sign();
//
//        return Base64.getEncoder().encodeToString(signature);
//    }
//
//    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception 
//    {
//        Signature publicSignature = Signature.getInstance("SHA256withRSA");
//        publicSignature.initVerify(publicKey);
//        publicSignature.update(plainText.getBytes(UTF_8));
//
//        byte[] signatureBytes = Base64.getDecoder().decode(signature);
//
//        return publicSignature.verify(signatureBytes);
//    }
//
//    public static String encrypt(String plainText, PublicKey publicKey) throws Exception 
//    {
//        Cipher encryptCipher = Cipher.getInstance("RSA");
//        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
//
//        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
//
//        return Base64.getEncoder().encodeToString(cipherText);
//    }
//
//    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception 
//    {
//        byte[] bytes = Base64.getDecoder().decode(cipherText);
//
//        Cipher decriptCipher = Cipher.getInstance("RSA");
//        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
//
//        return new String(decriptCipher.doFinal(bytes), UTF_8);
//    }

//    // Utility function to store prime factors of a number 
//    public static void findPrimefactors(ArrayList<BigInteger> s , BigInteger n) 
//    { 
//        int two1 =2;
//        BigInteger two = BigInteger.valueOf(two1);
//        int three1 =3;
//        BigInteger three = BigInteger.valueOf(three1);
//
//        // Print the number of 2s that divide n 
//        while (n.mod(two).compareTo(BigInteger.ZERO)==0) 
//        { 
//            s.add(two); 
//            n = n.divide(two); 
//        } 
//    
//        // n must be odd at this point. So we can skip 
//        // one element (Note i = i +2) 
//        for (BigInteger i = three; i.compareTo(n.pow(2))==-1; i.add(two)) 
//        { 
//            // While i divides n, print i and divide n 
//            while (n.mod(i).compareTo(BigInteger.ZERO) == 0) 
//            { 
//                s.add(i); 
//                n = n.divide(i); 
//            } 
//        } 
//    
//        // This condition is to handle the case when 
//        // n is a prime number greater than 2 
//        if (n.compareTo(two)==0 )
//            s.add(n); 
//    }

//    public static BigInteger generateG(BigInteger prime)
//    {
//        int two1 =2;
//        BigInteger two = BigInteger.valueOf(two1);
//        int three1 =3;
//        BigInteger three = BigInteger.valueOf(three1);
//
//        ArrayList<BigInteger> s = new ArrayList<BigInteger>(); 
//    
//        // Find value of Euler Totient function of n 
//        // Since n is a prime number, the value of Euler 
//        // Totient function is n-1 as there are n-1 
//        // relatively prime numbers. 
//        BigInteger phi = prime.subtract(BigInteger.ONE); 
//    
//        // Find prime factors of phi and store in a set 
//        findPrimefactors(s, phi);  
//    
//        // Check for every number from 2 to phi 
//        for (BigInteger r=two; r.compareTo(phi)==-1; r.add(BigInteger.ONE)) 
//        { 
//            // Iterate through all prime factors of phi. 
//            // and check if we found a power with value 1 
//            boolean flag = false;
//
//            for (int i = 0; i < s.size(); i++) 
//            { 
//                // Check if r^((phi)/primefactors) mod n 
//                // is 1 or not 
//                if ( (r.modPow((phi.divide(s.get(i))),prime)).compareTo(BigInteger.ONE)==0) 
//                { 
//                    flag = true; 
//                    break; 
//                } 
//            } 
//    
//            // If there was no power with value 1. 
//            if (flag == false) 
//            return r; 
//        } 
//        return two;
// 
//    }



//    public static BigInteger generatePrime()
//    {
//        BigInteger safeP;
//        int two1 =2;
//        BigInteger two = BigInteger.valueOf(two1);
//		/*7 is a known prime that doesn't generate a safe prime when*/
//		/*You plug it in, creates 15, so the while loops as long as a safe prime is not found*/
//		while(true)
//		{
//            /*generates random prime numbers*/
//            SecureRandom rnd1=new SecureRandom();
//            int bits = 1024;
//			safeP =BigInteger.probablePrime(bits, rnd1);
//			
//			/*Creates a safe prime*/
//			safeP = (safeP.multiply(two)).add(BigInteger.ONE);
//			
//			/*Checks if it is still a prime after calculations also has to be positive*/
//            if (isPrime(safeP))
//            {
//				return safeP;
//            }
//        }
//
//    }

//    public static boolean isPrime(BigInteger number) 
//    { 
//        int two1 =2;
//        BigInteger two = BigInteger.valueOf(two1);
//        int three1 =3;
//        BigInteger three = BigInteger.valueOf(three1);
//
//        //if 2 or 3 return true
//        if(number.compareTo(two) == 0 || number.compareTo(three) == 3) 
//        { 
//            return true; 
//        } 
//        //if even number
//        if(number.mod(two).compareTo(BigInteger.ZERO)==0) 
//        { 
//            return false; 
//        } 
//
//        int sqrt = (int) Math.sqrt(number) + 1; 
//
//        for(int i = 3; i < sqrt; i += 2) 
//        { 
//            if (number % i == 0) 
//            { 
//                return false; 
//            } 
//        } 
//
//        BigInteger sqrt = (number.pow(2)).add(BigInteger.ONE);
//        for(BigInteger i = BigInteger.valueOf(three1);i.compareTo(sqrt)==-1; i.add(two))
//        {
//            if(number.mod(i).compareTo(BigInteger.ZERO)==0)
//            {
//                return false;
//            }
//        }
//        //can't find so is true
//        return true; 
//    }


    
}