package proxy_server;
/*
 * @kasaquan
 * proxy_server for secure multiplication 2PC
 * */
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.Vector;
import java.math.BigInteger;

import crypto_scheme.CryptoException;
import crypto_scheme.Scheme;

public class ProxyServer {
	public static void main(String[] args) throws IOException{
			
		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(2222);
		} catch (IOException e){
			System.err.println("Could not listen on port 2222");
			System.exit(1);
		}
		
		Socket clientSocket = null;
		try{
			clientSocket = serverSocket.accept();
		} catch(IOException e){
			System.err.println("Accept failed.");
			System.exit(1);
		}
		
		PrintStream out = new PrintStream(clientSocket.getOutputStream(),true);
		BufferedInputStream in = new BufferedInputStream(clientSocket.getInputStream());
		byte[] inputLine = new byte[20];
		byte[] outputLine;
		BigInteger inBig = BigInteger.ZERO;
		BigInteger outBig = BigInteger.ZERO;
		int bytenum = 0;
		byte[] theInput = null;
		
		
		// generates new set of keys upon initiation
		ProxyProtocol pp = new ProxyProtocol();
		
		// for test
		pp.primegen();
		pp.generatePrivateKey();
		Vector<BigInteger> keys = pp.generatePublicKeys();
		
		while(in.available() ==0)
			;
		while( in.available() >0){
			bytenum = in.available();
			System.out.println("bytenum: "+bytenum);
			in.read(inputLine, 0, bytenum);
			theInput = new byte[bytenum]; 
			System.arraycopy(inputLine, 0, theInput, 0, bytenum);
			inBig = new BigInteger(theInput);
			theInput = null; //release
			System.out.println("Recieved:@Proxy "+ inBig);
			
			try {
				outBig =pp.processInput(inBig);
			} catch (CryptoException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (outBig!=null)
			{
				outputLine = outBig.toByteArray();
				out.write(outputLine,0,outputLine.length);
				System.out.println("Reply sent!@Proxy " + outBig);
			}
			
			while(in.available() ==0)
				;
		}
		
		System.out.println("Close connection @Proxy");
		out.close();
		in.close();
		clientSocket.close();
		serverSocket.close();
	}
}
