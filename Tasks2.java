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
import java.util.Random;
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

//        int newP = generatePrime();
//        int newG = generateG(newP);
//        int n = newP*newG;
//        int m = (newP-1)*(newG-1);
//
//        int e = generateE(m);
//        int d = generateD(e,n);
        BigInteger newP = generatePrime();
        System.out.println("newP " + newP);
//        BigInteger newG = generateG(newP);
        BigInteger newQ = generatePrime();
        System.out.println("\nnewQ "+ newQ);
        BigInteger newG = generatePrime();
        System.out.println("\nnewG "+ newG);
        BigInteger n = newP.multiply(newQ);
        System.out.println("\nn "+n);

        //m=(p-1)(q-1)
        BigInteger m = (newP.subtract(BigInteger.ONE)).multiply(newQ.subtract(BigInteger.ONE));
        System.out.println("\nm "+m);
        BigInteger e = generateE(m);
        System.out.println("\ne "+e);
        BigInteger d = generateD(e,n);
        System.out.println("\nd "+d);

        BigInteger BobPrivate=generatePrivateKey(newP);
        BigInteger AlicePrivate=generatePrivateKey(newP);
        System.out.println("\nBob generates private key "+BobPrivate);
        System.out.println("\nAlice generates private key "+AlicePrivate);

        BigInteger BobPublic=generatePublicKey(newG,BobPrivate,newP);
        BigInteger AlicePublic=generatePublicKey(newG,AlicePrivate,newP);
        System.out.println("\nBob generates public key "+BobPublic);
        System.out.println("\nAlice generates public key "+AlicePublic);

        System.out.println("\nAlice generates a random number x: ");
        int x = sc.nextInt();
        System.out.println("\nthen send g^x to Bob\n");

        System.out.println("\nBob generates a random number y: ");
        int y = sc.nextInt();

        System.out.println("\nBob generates a random number g^y: "  );


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
    public static BigInteger generateD(BigInteger e,BigInteger n)
    {
        BigInteger d;

        d = ((BigInteger.ONE.mod(n)).divide(e));

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

//            System.out.println("gcd "+m.gcd(e)+"\nvalue of m "+ m +"\nvalue of e "+ e);

            //gcd =1 and 1 < e < m-1
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

//    public static BigInteger generateG(BigInteger prime)
//    {
//        BigInteger g;
//        int zero = 0;
//        while(true)
//        {
//            int bitLength= 1024;
//            SecureRandom rnd2=new SecureRandom();
//            g=BigInteger.probablePrime(bitLength, rnd2);
//
//            if (prime.compareTo(g)==1 && g.intValue()>0)
//            {
//				return g;
//            }
//        }
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
//        if(number.mod(two)== 0) 
//        { 
//            return false; 
//        } 
//
//        //int sqrt = (int) Math.sqrt(number) + 1; 
////
//        //for(int i = 3; i < sqrt; i += 2) 
//        //{ 
//        //    if (number % i == 0) 
//        //    { 
//        //        return false; 
//        //    } 
//        //} 
//
//        BigInteger sqrt = (number.pow(2)).add(BigInteger.ONE);
//        for()
//        {
//            
//        }
//        //can't find so is true
//        return true; 
//    }


    
}