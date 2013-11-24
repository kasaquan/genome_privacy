package crypto_scheme;

/**
 * Represents an exception that can occur when encrypting or decrypting data.
 *
 * @author raisaro
 */

public class CryptoException extends Exception {

    /**
     * Constructs a new CryptoException instance with the
     * specified detail message.
     *
     * @param message The detailed error message.
     */

    public CryptoException( String message ) {

	super( message );

    }

} 
