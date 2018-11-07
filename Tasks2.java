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
        BigInteger newG = generateG(newP);
        BigInteger n = newP.multiply(newG);
        //for calculation purposes
        int newP1 = newP.intValue()-1;
        int newG1 = newG.intValue()-1;

        BigInteger m = BigInteger.valueOf(newP1).multiply(BigInteger.valueOf(newG1));
//TODO need to work on this section
        BigInteger e = generateE(m);
        BigInteger d = generateD(e,n);


        System.out.println("An asymmetric signature keypair for each party has been generated\n");
        System.out.println("Safe prime and Generator has been created as well\n");

        System.out.println("prime " + newP+"\n");
        System.out.println("generator " + newG+"\n");

        System.out.println("Alice generates a random number x: ");
        int x = sc.nextInt();
        System.out.println("then send g^x to Bob\n");

        System.out.println("Bob generates a random number y: ");
        int y = sc.nextInt();


        //K=(g^x)^y
        int BobK = computeExp(computeExp(newG,x),y);
        System.out.println("Bob computates the shared key K=(g^x)^y: "+BobK);

//        int biGX = Integer.toBinaryString(computeExp(newG,x));
//        int biGY = Integer.toBinaryString(computeExp(newG,y));

        System.out.println("xbinary: "+computeExp(newG,x));
        System.out.println("\nybinary: "+computeExp(newG,y));

        //concatenate binery or string?

        //signs the concatenated string with his private key

        //encrypts the signature with K

        //sends cipher text with his g^y to Alice

        //Alice then computes K=(g^y)^x




    }

    public static BigInteger generateD(BigInteger e,BigInteger n)
    {
        int d;
        d= (1%n)/e;
        return d;
    }
    public static BigInteger generateE(BigInteger m)
    {
        Random rand = new Random();
        int bigM = m;
        int e = 0;
        //while gcd isnt 1
        while(true)
        {
            e = rand.nextInt(m) + 2;

            if(findGCD(e,bigM)==1)
            {
                System.out.println("e is: "+e);
                return e;
            }
        }
    }
    private static BigInteger findGCD(BigInteger number1, BigInteger number2) 
    { 
        //base case 
        if(number2 == 0)
        { 
            return number1; 
        } 
        return findGCD(number2, number1%number2); 
    }


    public static int computeExp(int g, int num)
    {
        double expNum = Math.pow(g,num);
        int newNum = (int) expNum;
        return newNum;
    }

    public static BigInteger generateG(BigInteger prime)
    {
        BigInteger g;
        int zero = 0;
        while(true)
        {
            int bitLength= 1024;
            SecureRandom rnd2=new SecureRandom();
            g=BigInteger.probablePrime(bitLength, rnd2).intValue();

            if (prime.compareTo(g)==1 && g.intValue()>0)
            {
				return g;
            }
        }
    }

    public static BigInteger generatePrime()
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
                BigInteger num = BigInteger.valueOf(safeP);
				return num;
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