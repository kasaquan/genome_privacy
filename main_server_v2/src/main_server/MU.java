/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package main_server;

import DGK_crypto_scheme.DGK_key_generator;
import DGK_crypto_scheme.DGK_scheme;
import crypto_scheme.CryptoException;
import crypto_scheme.Scheme;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.ListIterator;

/**
 *
 * @author raisaro
 */
public class MU {
    
    private BigInteger mu_privateKey;
    private BigInteger[] publicKey;
    private DGK_scheme dgk_scheme;

    public MU(BigInteger mu_privateKey, BigInteger[] publicKey) {
        this.mu_privateKey = mu_privateKey;
        this.publicKey = publicKey;
    }

    public BigInteger getMu_privateKey() {
        return mu_privateKey;
    }

    public void setMu_privateKey(BigInteger mu_privateKey) {
        this.mu_privateKey = mu_privateKey;
    }

    public BigInteger[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger[] publicKey) {
        this.publicKey = publicKey;
    }
    
    public ArrayList comparisonProtocol(BigInteger[] cipherD_proxy) throws CryptoException {
        
        ArrayList results = new ArrayList();
        
        //initiate values        
        BigInteger n = this.publicKey[0];
        BigInteger g = this.publicKey[1];
        BigInteger h = this.publicKey[2];
        BigInteger nsqr = n.multiply(n);
        
        //number of bits for the max value of a or b in plaintext
	//int l = BigInteger.valueOf(359).bitLength();
        
        
        int l = MainServer.l;
        BigInteger twoPowL = BigInteger.valueOf(2).pow(l);
        
        int t = 160;
        int kk = 1024;
        
        DGK_key_generator kg = new DGK_key_generator(kk, t, l);
        kg.generateKeys();
        
        BigInteger[] pk = {kg.getN(), kg.getG(), kg.getH(), kg.getU()};
        BigInteger[] sk = {kg.getP(), kg.getQ(), kg.getVpvq(), kg.getPp_inv(), kg.getQq_inv()};
        
        
        
        DGK_scheme dgk_s = new DGK_scheme(pk, sk, kk, t, l);
        this.dgk_scheme = dgk_s;
        
        
        //generate the encryption scheme for homomorphic operations
        Scheme s = new Scheme(n, g, h, mu_privateKey);
        //request for private key here, put in and out as paras
        
        
        //decryption of cipherD_proxy
        BigInteger D = s.decrypt(cipherD_proxy);
        
        //reduction of D in mod 2^L
        BigInteger Dmod = D.mod(twoPowL);
        
        //encryption of Dmod's bits using the DGK scheme
        ArrayList<BigInteger> cipherDi = new ArrayList<BigInteger>();
        int numBit_Dmod = Dmod.bitLength();
        for(int i=0;i<numBit_Dmod;i++){
            
            BigInteger bitvalue;
            boolean bol = Dmod.testBit(i);
            if(bol)
                bitvalue = BigInteger.ONE;
            else
                bitvalue = BigInteger.ZERO;
            cipherDi.add(dgk_s.encryption(bitvalue));
        }
        
        //encryption of Dmod
        BigInteger[] cipherDmod = s.encrypt(Dmod);
        
        results.add(cipherDmod);
        results.add(pk);
        results.add(cipherDi);
        
        
        return results;
        
        
    }
    
    public BigInteger[] computeCipherLamda(ArrayList<BigInteger> cipherCi) throws CryptoException{
        
        BigInteger lamda = null;
        
        ListIterator<BigInteger> iterator = cipherCi.listIterator();
        while(iterator.hasNext()){
            boolean zero_test = dgk_scheme.decryptionZero(iterator.next());
            System.out.println("c = " + zero_test);
            if (zero_test){
                lamda = BigInteger.ONE;
                break;
            }else{
                lamda = BigInteger.ZERO;
            }
                
        }
        //initiate values        
        BigInteger n = this.publicKey[0];
        BigInteger g = this.publicKey[1];
        BigInteger h = this.publicKey[2];
        BigInteger nsqr = n.multiply(n);
        Scheme s = new Scheme(n, g, h, mu_privateKey);
        System.out.println("lamda = " + lamda);
        BigInteger[] cipherLamda = s.encrypt(lamda);
        
        return cipherLamda;
        
    }
}
