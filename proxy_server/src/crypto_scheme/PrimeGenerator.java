/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto_scheme;

import java.math.BigInteger;
import java.util.Vector;

/**
 *
 * @author raisaro
 */
public class PrimeGenerator {
    
    private BigInteger gen; // This number occurs just before the
                            // smallest generated prime.

    /**
     * Initializes the generator.
     */

    public PrimeGenerator() {

	gen = BigInteger.ONE;

    }

    /**
     * Obtains a specified number of primes.
     *
     * @param start No primes will be returned whose values are less than this.
     * @param num The number of primes to generate.
     *
     * @return A list of prime integers.
     */

    public Vector< Long > getPrimes( long start, int num ) {

	Vector< Long > p; // The primes found.

	p = new Vector< Long >( num );
	gen = BigInteger.valueOf( start - 1 );
	for( int i = 0; i < num; i++ ) {
	    gen = gen.nextProbablePrime();
	    p.add( gen.longValue() );
	}

	return p;

    }

    /**
     * Obtains a specified number of primes.
     *
     * @param digits The primes must have at least this number of digits.
     * @param num The number of primes to generate.
     *
     * @return A list of prime numbers.
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

    /**
     * Obtains all primes within a range of values. The lower and
     * upper bound are inclusive, so they will appear in the list of
     * primes if they are prime values.
     *
     * @param lb Lower bound of the range.
     * @param ub Upper bound of the range.
     *
     * @return A list of prime integers.
     */

    public Vector< Long > getPrimesBetween( long lb, long ub ) {

	Vector< Long > p; // The primes found.
	BigInteger stop;  // Indicates when to stop generating values.

	p = new Vector< Long >();
	gen = BigInteger.valueOf( lb - 1 );
	stop = BigInteger.valueOf( ub );
	while( gen.compareTo( stop ) <= 0 ) {
	    gen = gen.nextProbablePrime();
	    p.add( gen.longValue() );
	}

	return p;

    }

    /**
     * Tests the prime generator by generating and printing out a
     * list of primes.
     *
     * @param args The number of primes to generate and the starting integer.
     */

//    public static void main( String[] args ) {
//
//	long start;        // Starting number (all primes will be >= start).
//	int num;           // Number of primes to generate.
//	PrimeGenerator pg; // Class instance used to generate primes.
//	Vector< Long > primes; // The primes returned by the generator.
//
//	// Check the number of arguments, and print out a usage
//	// message if it isn't right.
//	if( args.length != 2 ) {
//	    System.err.println( "Usage: java PrimeGenerator n start" );
//	    System.err.println( "<n> = number of primes" );
//	    System.err.println( "<start> = starting integer" );
//	    System.exit( 1 );
//	}
//
//	try {
//	    // Obtain the arguments and instantiate the prime generator.
//	    num = Integer.parseInt( args[ 0 ] );
//	    start = Long.parseLong( args[ 1 ] );
//	    pg = new PrimeGenerator();
//	    // Obtain and print out the primes from the generator.
//	    primes = pg.getPrimes( start, num );
//	    for( int i = 0; i < primes.size(); i++ ) {
//		System.out.println( primes.get( i ) );
//	    }
//	} catch( NumberFormatException n ) {
//	    System.err.println( "One of the arguments is not a number. " +
//	        "Please try again." );
//	    System.exit( 1 );
//	}
//
//    }
}
