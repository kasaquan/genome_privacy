/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package main_server;

import DGK_crypto_scheme.DGK_scheme;
import crypto_scheme.CryptoException;
import crypto_scheme.Scheme;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

/**
 *
 * @author raisaro
 */
public class SPU {
    
    private MU mu;
    private BigInteger spu_privateKey;
    private BigInteger[] publicKey;

    public SPU(BigInteger spu_privateKey, BigInteger[] publicKey) {
        this.spu_privateKey = spu_privateKey;
        this.publicKey = publicKey;
    }

    public MU getMu() {
        return mu;
    }

    public void setMu(MU mu) {
        this.mu = mu;
    }

    public BigInteger[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger[] publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getSpu_privateKey() {
        return spu_privateKey;
    }

    public void setSpu_privateKey(BigInteger spu_privateKey) {
        this.spu_privateKey = spu_privateKey;
    }
    
    public BigInteger[] compareEncryptedValues(BigInteger[] cipherA, BigInteger[] cipherB) throws CryptoException{
        
        //initiate values        
        BigInteger n = this.publicKey[0];
        BigInteger g = this.publicKey[1];
        BigInteger h = this.publicKey[2];
        BigInteger nsqr = n.multiply(n);
        
        
        //number of bits for the max value of a or b in plaintext
        //int l = BigInteger.valueOf(359).bitLength();
        int l = MainServer.l;
        BigInteger twoPowL = BigInteger.valueOf(2).pow(l);
        
        //generate the encryption scheme for homomorphic operations
        Scheme s = new Scheme(n, g, h, spu_privateKey);
        
        //encryption of 2^L
        BigInteger[] cipher = s.encrypt(twoPowL);
        
        //computation of cipherZ in plaintext: z = 2^L + a - b
        BigInteger[] cipherZ = new BigInteger[2];
        cipherZ[0]=(cipher[0].multiply(cipherA[0]).multiply(cipherB[0].modInverse(nsqr))).mod(nsqr);
        cipherZ[1]=(cipher[1].multiply(cipherA[1]).multiply(cipherB[1].modInverse(nsqr))).mod(nsqr);
        
        //generation of the random blind facto r 
        int k = 100; //security factor
        int r_bit_length = k+l+1;
        BigInteger r = new BigInteger(r_bit_length, new Random());
        BigInteger[] cipherR = s.encrypt(r);
        BigInteger Rmod = r.mod(twoPowL);
        BigInteger[] cipherRmod = s.encrypt(Rmod);
        
        //computation of encrypted d in plaintext: d = z + r
        BigInteger[] cipherD = new BigInteger[2];
        cipherD[0]=(cipherZ[0].multiply(cipherR[0])).mod(nsqr);
        cipherD[1]=(cipherZ[1].multiply(cipherR[1])).mod(nsqr);
        
        //partial decription of D
        BigInteger[] cipherD_proxy = s.proxyDecription(cipherD);
        
        
        ArrayList mu_interaction_results = mu.comparisonProtocol(cipherD_proxy);
        
        //Getting cipherDmod encryption of D mod 2^L from MU
        BigInteger[] cipherDmod = (BigInteger[]) mu_interaction_results.get(0);
        
        //Getting DGK public key from MU in order to compute [[Ci]] encrypted with DGK scheme
        BigInteger[] pk = (BigInteger[]) mu_interaction_results.get(1);
        
        //Getting Dmod dkg-encrypted bits from MU
        ArrayList<BigInteger> cipherDi = (ArrayList<BigInteger>) mu_interaction_results.get(2);
        
        //DGK_scheme generation
        int t = 160;
        int kk = 1024;
        DGK_scheme dgk_s = new DGK_scheme(pk, t, l, kk);
        
        // Bob side: encryption of every single bit of r mod 2^l with DGK scheme
        BigInteger s_param = BigInteger.ONE;
        BigInteger cs_param = dgk_s.encryption(s_param);
        
        ArrayList<BigInteger> cipherRi = new ArrayList<>();
        ArrayList<BigInteger> plainRi = new ArrayList<>();
        int numBit_Rmod = Rmod.bitLength();
        for(int i=0;i<numBit_Rmod;i++){
            
            BigInteger bitvalue;
            boolean bol = Rmod.testBit(i);
            if(bol)
                bitvalue = BigInteger.ONE;
            else
                bitvalue = BigInteger.ZERO;
            cipherRi.add(dgk_s.encryption(bitvalue));
            plainRi.add(bitvalue);
        }  
        
        // Bob computes [[ci]] = [[ di - ri + s + 3sum(wj)]] = [[di]][[-ri]][[s]]prod([[wj]])^3
        
        ArrayList<BigInteger> cipherCi = new ArrayList<>();
        for(int i=0;i<numBit_Rmod;i++){
            
            BigInteger tmp1, tmp2, tmp3, tmp4;
            tmp1 = cipherRi.get(i).modInverse(pk[0]);
            tmp1 = cipherDi.get(i).multiply(tmp1);
            tmp1 = tmp1.multiply(cs_param);
            tmp2 = dgk_s.encryption(BigInteger.ZERO);
            
            //computing product(Wj) j=i+1,...,l-1;
            for(int j=i+1;j<numBit_Rmod;j++){
                //computing wj
                BigInteger exp = plainRi.get(j).multiply(BigInteger.valueOf(2));
                tmp3 = cipherDi.get(j).multiply(cipherRi.get(j));
                tmp4 = cipherDi.get(j).modInverse(pk[0]);
                tmp4 = tmp4.modPow(exp, pk[0]);
                BigInteger w = (tmp3.multiply(tmp4)).mod(pk[0]);
                
                tmp2 = (tmp2.multiply(w)).mod(pk[0]);
                
            
            }
            
            //computing Ci 
            tmp2 = tmp2.modPow(BigInteger.valueOf(3), pk[0]);
            BigInteger c = tmp1.multiply(tmp2);
            c = c.mod(pk[0]);
            cipherCi.add(c);
            
        }
        
        //Getting cipherLamda from MU
        BigInteger[] cipherLamda = (BigInteger[]) this.mu.computeCipherLamda(cipherCi);
         
        //Computing cipherZmod
        BigInteger[] cipherZmod = new BigInteger[2];
        
        cipherZmod[0]=((cipherDmod[0].multiply(cipherRmod[0].modInverse(nsqr)).multiply(cipherLamda[0].modPow(twoPowL, nsqr))).mod(nsqr));
        cipherZmod[1]=((cipherDmod[1].multiply(cipherRmod[1].modInverse(nsqr)).multiply(cipherLamda[1].modPow(twoPowL, nsqr))).mod(nsqr));
        
        //Computing cipherZL
        BigInteger[] cipherZL = new BigInteger[2];
        cipherZL[0] = (cipherZ[0].multiply(cipherZmod[0].modInverse(nsqr))).mod(nsqr);
        cipherZL[1] = (cipherZ[1].multiply(cipherZmod[1].modInverse(nsqr))).mod(nsqr);
        
        
        return cipherZL;
        
    }
    
}
