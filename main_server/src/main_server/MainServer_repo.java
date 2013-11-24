package main_server;

/*
 * main_server
 * not the proxy
 * modified from echo client
 * @kasaquan
 */

import java.io.*;
import java.net.*;
import java.util.Vector;
import java.math.BigInteger;

import crypto_scheme.Scheme;


public class MainServer{
	private static final BigInteger KREQ = BigInteger.valueOf(255);
	private static final BigInteger NRECD = BigInteger.valueOf(254);
	private static final BigInteger GRECD = BigInteger.valueOf(253);
	private static final BigInteger HRECD = BigInteger.valueOf(252);
	private static final BigInteger KEYSENT = BigInteger.valueOf(251);
	private static final BigInteger MREQ = BigInteger.valueOf(250);
	private static final BigInteger MREADY = BigInteger.valueOf(249);
	private static final BigInteger MSENT = BigInteger.valueOf(248);
	
	public static BigInteger N;
	public static BigInteger G;
	public static BigInteger H;
	public static Vector<BigInteger> keys = new Vector<BigInteger>(3);
	public static Scheme scm;
	
	/*data to be seperated!*/
	

	public static void main(String[] args) throws IOException{
		
		Socket proxySocket = null;
		PrintStream out = null;
		BufferedInputStream in = null;
		
		try{
			proxySocket = new Socket("localhost",2222);
			out = new PrintStream(proxySocket.getOutputStream(),true);
			in = new BufferedInputStream (proxySocket.getInputStream());
		}catch (UnknownHostException e){
			System.err.println("Don't know about the host");
			System.exit(1);
		}catch (IOException e){
			System.err.println("Couldn't get I/O for the connection");
			System.exit(1);
		}
		
		System.out.println("connection setup @ main");
		
		
		
		byte[] inputLine = new byte[20];
		byte[] outputLine;
		BigInteger inBig = BigInteger.ZERO;
		BigInteger outBig = BigInteger.ZERO;
		int bytenum = 0;
		byte[] theInput = null;
	

		int keyctr  = 0;
		
		outputLine = KREQ.toByteArray();
		out.write(outputLine,0,outputLine.length);
		System.out.println("Request sent!@Main " + outputLine);
		
		/*waiting for inputs*/
		while(in.available() ==0)
			;
		
		while( in.available()>0){
			bytenum = in.available();
			System.out.println(bytenum);
			in.read(inputLine, 0, bytenum);
			theInput = new byte[bytenum]; 
			System.arraycopy(inputLine, 0, theInput, 0, bytenum);
			inBig = new BigInteger(theInput);
			theInput = null; //release
			System.out.println("Recieved:@Main "+ inBig);
			
			if(inBig.compareTo(KEYSENT)!= 0)
			{
				keys.addElement(inBig);
				switch(keyctr){
				case 0:	keyctr ++; outBig = NRECD;break;
				case 1:	keyctr ++; outBig = GRECD;break;
				case 2:	keyctr ++; outBig = HRECD;break;
				}
			}else
			{
				keyctr = 0;
				N = keys.elementAt(0);
				G = keys.elementAt(1);
				H = keys.elementAt(2);
				outBig = BigInteger.ZERO;
			}
				
			if (outBig != BigInteger.ZERO)
			{
				outputLine = outBig.toByteArray();
				out.write(outputLine,0,outputLine.length);
				System.out.println("Request sent!@Main" + outBig);
			}else 
				break;
			
			while(in.available() ==0)
				;
		}
		
		System.out.println(N);
		System.out.println(G);
		System.out.println(H);
		scm =  new Scheme(N,G,H);	// new encryption scheme generated!
		System.out.println("Encryption scheme setup!");
		
		/**
		 * secure multiplication part*/
		outputLine = MREQ.toByteArray();
		out.write(outputLine,0,outputLine.length);
		System.out.println("Request sent!@Main " + MREQ);
		BigInteger[] pairA = new BigInteger[2];
		BigInteger[] pairB = new BigInteger[2];
		// organize mdata to be sent
		int mctr = 0;
		Vector<BigInteger> mdata = new Vector<BigInteger>(4);
		BigInteger[] mresult = new BigInteger[2];
		// add some random here
		mdata.addElement(pairA[0]);
		mdata.addElement(pairA[1]);
		mdata.addElement(pairB[0]);
		mdata.addElement(pairB[1]);
		
		while(in.available() ==0)
			;
		while(in.available()>0){
			bytenum = in.available();
			System.out.println(bytenum);
			in.read(inputLine, 0, bytenum);
			theInput = new byte[bytenum]; 
			System.arraycopy(inputLine, 0, theInput, 0, bytenum);
			inBig = new BigInteger(theInput);
			theInput = null; //release
			System.out.println("Recieved:@Main "+ inBig);
				
			if (bytenum == 2)
			{
				if(inBig.compareTo(MREADY)== 0)
				{
					outBig = mdata.elementAt(mctr);
					mctr ++;
				}
				if (mctr == 4)
					mctr=0;
			}else {
				mresult[mctr] = inBig;
				mctr++;
				if (mctr < 2)
					outBig = BigInteger.ZERO;
				else 
					{mctr =0;break;}
			}
			// deal with the result here
			

			outputLine = outBig.toByteArray();
			out.write(outputLine,0,outputLine.length);
			System.out.println("MDATA sent!@Main" + outBig);
			
			while(in.available() ==0)
				;
		}
		
		
		
		System.out.println("Close connection @Main");
		out.close();
		in.close();
		proxySocket.close();
	} 
	
}