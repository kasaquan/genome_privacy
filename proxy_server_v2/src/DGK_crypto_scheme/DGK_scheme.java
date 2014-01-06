/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package DGK_crypto_scheme;

import crypto_scheme.CryptoException;
import java.math.BigInteger;
import java.util.Random;

/**
 *
 * @author raisaro
 */
public class DGK_scheme {
    
    // scheme parameter
    private int k;
    private int t;
    private int l;
    
    // public key
    private BigInteger n;
    private BigInteger g;
    private BigInteger h;
    private BigInteger u;
    
    //private key
    private Boolean canDecrypt;
    private BigInteger p;
    private BigInteger q;
    private BigInteger vpvq;
    
    //CRT parameters
    private Boolean secretKeyValid;
    private BigInteger pp_inv;
    private BigInteger qq_inv;
    
    public DGK_scheme(BigInteger[] pk, BigInteger[] sk, int ka, int ti, int ell){
        
        if (sk.length > 3){
            secretKeyValid = true;
            pp_inv = sk[3];
            qq_inv = sk[4];
        }
        else
            secretKeyValid = false;
        n = pk[0];
        g = pk[1];
        h = pk[2];
        u = pk[3];
        
        p = sk[0];
        q = sk[1];
        vpvq = sk[2];
        
        k = ka;
        t = ti;
        l = ell;
        canDecrypt = true;
                
    }
    
    public DGK_scheme(BigInteger[] pk, int ti, int ell, int ka){
         
        secretKeyValid = false;
        n = pk[0];
        g = pk[1];
        h = pk[2];
        u = pk[3];
        t = ti;
        l = ell;
        k = ka;
        canDecrypt = false;
        
                
    }
    
    /**
     * Standard DGK encryption
     * @param message
     * @return E[message, r] = cipher
     */
    public BigInteger encryption(BigInteger message){
        BigInteger tmp1;
        BigInteger tmp2;
        BigInteger cipher;
        
        tmp1 = new BigInteger(t*2, new Random(System.currentTimeMillis()));
        tmp2 = h.modPow(tmp1, n);
        tmp1 = g.modPow(message, n);
        cipher = tmp1.multiply(tmp2);
        cipher = cipher.mod(n);
        
        return cipher;
    }
    
    /**
     * DGK encryption using CRT for the owner of the private key. It is faster
     * than the standard DGK encryption.
     * @param message
     * @return E[message, r] = cipher
     */
    public BigInteger ecryptionCRT(BigInteger message) throws CryptoException{
        if (!secretKeyValid){
            throw new CryptoException("Cannot encrypt value" + 
                    message + "because the secret key is not valid");
        }
        
        BigInteger cipher;
        BigInteger tmp1, tmp2, tmp3, tmp_cp, tmp_cq;
        
        // Use Zv instead of a 2t bit number:
        Random rnd = new Random(System.currentTimeMillis());
        long rand;
        rand = Math.abs( rnd.nextLong() ) % vpvq.longValue();
        tmp3 = BigInteger.valueOf( rand );
        
        // Calculate in Zp and Zq instead of Zn:
        tmp1 = g.modPow(message, p);
        tmp2 = h.modPow(tmp3, p);
        tmp_cp = tmp1.multiply(tmp2);
        
        tmp1 = g.modPow(message, q);
        tmp2 = h.modPow(tmp3, q);
        tmp_cq = tmp1.multiply(tmp2);
        
        tmp1 = tmp_cp.multiply(qq_inv);
        tmp2 = tmp_cq.multiply(pp_inv);
        tmp1 = tmp1.add(tmp2);
        cipher = tmp1.mod(n);
        
        return cipher;
        
    }
    
    /**
     * DGK "zero decryption". 
     * This method only checks if or not the ciphertext is an encryption of zero, or not
     * @param cipher
     * @return true if the cipher is an encryption of zero, false otherwise
     * @throws CryptoException 
     */
    public boolean decryptionZero(BigInteger cipher) throws CryptoException{
        if (!canDecrypt){
            throw new CryptoException("Cannot dencrypt value because the secret "
                    + "key is not stored in the scheme");
        }
        
        BigInteger tmp1;
        
        tmp1 = cipher.modPow(vpvq, n);
        int res = tmp1.compareTo(BigInteger.ONE);
        
        return (res == 0);
        
    }
    
    
    /**
     * DGK "zero decryption". Using CRT. 
     * This method only checks if or not the ciphertext is an encryption of zero, or not
     * @param cipher
     * @return true if the cipher is an encryption of zero, false otherwise
     * @throws CryptoException 
     */
    public boolean decryptionZeroCRT(BigInteger cipher) throws CryptoException{
        if (!canDecrypt){
            throw new CryptoException("Cannot dencrypt value because the secret "
                    + "key is not stored in the scheme");
        }
        
        BigInteger tmp1, tmp2, tmp_cp, tmp_cq;
        
        tmp_cp = cipher.modPow(vpvq, p);
        tmp_cq = cipher.modPow(vpvq, q);
        tmp1 = tmp_cp.multiply(qq_inv);
        tmp2 = tmp_cq.multiply(pp_inv);
        tmp1 = tmp1.add(tmp2);
        tmp2 = tmp1.mod(n);
        
        int res = tmp2.compareTo(BigInteger.ONE);
        
        return (res == 0);
        
    }
    
    /**
     * DGK Decryption.
     * This method can be used for decryption
     * @param cipher
     * @return
     * @throws CryptoException 
     */
    public BigInteger decryption(BigInteger cipher) throws CryptoException{
        if (!canDecrypt){
            throw new CryptoException("Cannot dencrypt value because the secret "
                    + "key is not stored in the scheme");
        }
        
        BigInteger tmp1, tmp2;
        BigInteger message;
        
        message = cipher.modPow(vpvq, n);
        int uff = u.intValue();
        tmp1 = g.modPow(vpvq, n);
        
        for(int i=0;i<uff;i++){
            tmp2 = tmp1.modPow(BigInteger.valueOf(i), n);
            int res = message.compareTo(tmp2);
            if(res == 0)
                message = BigInteger.valueOf(i);
            
                      
        }
        return message;
    }
    
    
    
}
