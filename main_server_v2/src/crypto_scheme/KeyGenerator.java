package crypto_scheme;
/*
 * @kasaquan
 * module for key generation*/

import java.math.BigInteger;
import java.util.Random;
import java.util.Vector;


public class KeyGenerator {
	private BigInteger p;
	private BigInteger q;
	private BigInteger N;	//product of 2 primes pq
	private BigInteger G;	//g of order (p − 1)(q − 1)/2
	private BigInteger H;	//g^x
	private BigInteger X;	//secret key
	private BigInteger gen; //
	private BigInteger nsqr;	//N^2
	private Random rnd;
	
	public BigInteger getN()
	{
		return N;
	}
	
	public BigInteger getG()
	{
		return G;
	}
	
	public BigInteger getH()
	{
		return H;
	}
	
	public BigInteger getX()
	{
		return X;
	}
	
	/**
	 * Generates 2 primes of 10 bits (1024)
	 * not always called before generate keys*/
	
	public void generatePrimes()
	{
		Vector<BigInteger> primes= getBigPrimes(10,2);
		p = primes.firstElement();
		q = primes.lastElement();
		N=p.multiply(q);
		nsqr = N.multiply(N);
		
		System.out.println("primes generated");
	}
	/**
	 * Generates Public Keys N,G,H
	 * N = p*q
	 * G^lamda(N) = 1
	 * H = G^X mod (N^2)*/
	public void generatePublicKeys()
	{
		//N=p.multiply(q);
		//nsqr = N.multiply(N);
		
		Random prng = new Random( System.currentTimeMillis() );
        long rand;
        rand = Math.abs( prng.nextLong() ) % nsqr.longValue();
        BigInteger a = BigInteger.valueOf( rand );
        G = a.modPow(BigInteger.valueOf(2), nsqr);
		H = G.modPow(X, nsqr);
		
		System.out.println("public keys generated");
	}
	
	
    /**
     * Generates a Private Key a random integer x € [1,n^2/2].
     */
	public void generatePrivateKey(){
		
		X = new BigInteger(2048, new Random());
        X = X.mod(nsqr.divide(BigInteger.valueOf(2)));
        X = X.add(BigInteger.ONE);
        
        System.out.println("private keys generated");
	}
	
	
    /**
     * Obtains a specified number of primes.
     *
     * @param digits The primes must have at least this number of digits.
     * @param num The number of primes to generate.
     *
     * @return A list of prime numbers.
     * copied by kasaquan from PrimeGenerator
     */

    public Vector< BigInteger > getBigPrimes( int digits, int num ) {

	Vector< BigInteger > p; // The primes found.
	String start;           // Primes must be greater than this number.

	p = new Vector< BigInteger >( num );
	start = String.valueOf( '1' );
	for( int i = 1; i < digits; i++ ) {
	    start = start.concat( "0" );
	}
	gen = new BigInteger( start );
	for( int i = 0; i < num; i++ ) {
	    gen = gen.nextProbablePrime();
	    p.add( gen );
	}

	return p;

    }

}
