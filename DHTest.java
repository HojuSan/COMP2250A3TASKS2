import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class DHTest {
    public BigInteger genP(){
        BigInteger p;
        int bitLength= 512;
        SecureRandom rnd1=new SecureRandom();
        p=BigInteger.probablePrime(bitLength, rnd1);
        return p;
    }
    public BigInteger genG(){
        BigInteger g;
        int bitLength= 512;
        SecureRandom rnd2=new SecureRandom();
        g=BigInteger.probablePrime(bitLength, rnd2);
        return g;
    }
    public BigInteger calpow(int x, BigInteger g){
        BigInteger val;
        val=g.pow(x);
        return val;
    }
    public BigInteger calMod(BigInteger Y, BigInteger p){
        BigInteger val;
        val=Y.mod(p);
        return val;
    }

    public static void main(String[] args) throws Exception {
        BigInteger P, G, A, B, xA, xB;

        DHTest dhTest=new DHTest();
        P=dhTest.genP();
        G=dhTest.genG();
        int a=45,b=67;
        A=dhTest.calpow(a,G);
        System.out.println("Value of A:"+dhTest.calMod(A,P));
        B=dhTest.calpow(b,G);
        System.out.println("Value of B:"+dhTest.calMod(B,P));
        // calculate a b in opposite case.
        xA=dhTest.calpow(a,B);
        System.out.println("Value of A Side:"+dhTest.calMod(xA,P));
        xB=dhTest.calpow(b,A);
        System.out.println("Value of B Side:"+dhTest.calMod(xB,P));
    }

}