package main_server;

/*
 * main_server
 * not the proxy
 * modified from echo client
 * @kasaquan
 */

import java.io.*;
import java.net.*;
import java.util.Random;
import java.util.Vector;
import java.math.BigInteger;

import crypto_scheme.CryptoException;
import crypto_scheme.Scheme;


public class MainServer{
	private static final BigInteger KREQ = BigInteger.valueOf(255);
	private static final BigInteger NRECD = BigInteger.valueOf(254);
	private static final BigInteger GRECD = BigInteger.valueOf(253);
	private static final BigInteger HRECD = BigInteger.valueOf(252);
	private static final BigInteger KFIN = BigInteger.valueOf(251);
	
	private static final BigInteger MREQ = BigInteger.valueOf(250);
	private static final BigInteger MACK = BigInteger.valueOf(249);
	
	private static final BigInteger DREQ = BigInteger.valueOf(248);
	private static final BigInteger DACK = BigInteger.valueOf(247);
	
	public static BigInteger N;
	public static BigInteger G;
	public static BigInteger H;
	public static Vector<BigInteger> keys = new Vector<BigInteger>(3);
	public static Scheme scm;
	public static long sent_overhead = 0;
	public static long receive_overhead = 0;
	
	/*data to be seperated!*/
	

	public static void main(String[] args) throws IOException, CryptoException{
		
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
	
		long starttime = System.currentTimeMillis();
		keyRequest(in,out);
		long t1 = System.currentTimeMillis();
		System.out.println("Keys@Main: "+N+" "+G+" "+H);
		scm =  new Scheme(N,G,H);	// new encryption scheme generated!
		System.out.println("Encryption scheme setup!");

		
		//mock computation of similarity without l and w paras
		/*data that should be stored elsewhere in some database*/
		BigInteger[] dataA = new BigInteger[500];
		BigInteger[] dataB = new BigInteger[500];
		for(int i=0; i<dataA.length;i++)
			dataA[i]=new BigInteger(2,new Random());
		for(int i=0; i<dataB.length;i++)
			dataB[i]=new BigInteger(2,new Random());
		BigInteger[] sqr_dataA = new BigInteger[500];
		BigInteger[] sqr_dataB = new BigInteger[500];
		for(int i=0; i<dataA.length; i++)
			sqr_dataA[i] = dataA[i].modPow(BigInteger.valueOf(2), N);
		for(int i=0; i<dataB.length; i++)
			sqr_dataB[i] = dataB[i].modPow(BigInteger.valueOf(2), N);
		BigInteger[] Numerator,Denominator,d1,d2;
		int len = 0;
		//calculate numerator
		BigInteger[] temp;
		len = dataA.length; //to be modified later
		BigInteger[] p1,p2;
		p1 = scm.encrypt(dataA[0]);
		p2 = scm.encrypt(dataB[0]);
		Numerator = secureMul(p1,p2,in,out);
		for(int i = 1;i<len; i++)
		{
			p1 = scm.encrypt(dataA[0]);
			p2 = scm.encrypt(dataB[0]);
			temp = secureMul(p1,p2,in,out);
			Numerator = scm.homo_add(temp,Numerator);
		}
		System.out.println("Numerator got!@Main");
		//calculate denominator
		d1 = scm.encrypt(sqr_dataA[0]);
		d2 = scm.encrypt(sqr_dataA[1]);
		for (int i =1; i<len; i++)
		{
			d1 = scm.homo_add(d1, scm.encrypt(sqr_dataA[i]));
			d1 = scm.homo_add(d1, scm.encrypt(sqr_dataB[i]));
		}
		Denominator = secureMul(d1,d2,in,out);
		System.out.println("Denominator got!@Main");
		//calculate similarity
		BigInteger[] sim =pro_div(Numerator,Denominator,in,out);
		System.out.println("Similarity got!@Main "+sim);
		long stoptime = System.currentTimeMillis();
		long totaltime = stoptime-starttime;
		System.out.println("Total time: "+ totaltime + "Key: "+ (t1-starttime));
				
		System.out.println("Close connection @Main");
		System.out.println("Send: "+sent_overhead+" Receive: "+receive_overhead);
		out.close();
		in.close();
		proxySocket.close();
	} 
	
	/**
	 * @author kasaquan
	 * keyRequest function to get public keys from proxy server*/
	public static void keyRequest(BufferedInputStream in, PrintStream out) throws IOException{
		/*no return paras, because N,G,H are static
		 * variables initial*/
		byte[] outputLine;
		byte[] inputLine = new byte[20];
		byte[] theInput = null;
		int bytenum = 0;
		BigInteger inBig = BigInteger.ZERO;
		BigInteger outBig = BigInteger.ZERO;
		int keyctr  = 0;
		
		/*sending key request*/
		outputLine = KREQ.toByteArray();
		out.write(outputLine,0,outputLine.length);
		System.out.println("keyRequest sent!@Main");
		
		/*waiting for inputs*/
		while(in.available() ==0)
			;
		while( in.available()>0){
			bytenum = in.available();
			in.read(inputLine, 0, bytenum);
			theInput = new byte[bytenum]; 
			System.arraycopy(inputLine, 0, theInput, 0, bytenum);
			inBig = new BigInteger(theInput);
			theInput = null; //release
			//System.out.println("Recieved:@Main "+ inBig);
			
			switch(keyctr){
			case 0:	keyctr ++; outBig = NRECD;N = inBig;break;
			case 1:	keyctr ++; outBig = GRECD;G = inBig;break;
			case 2:	keyctr ++; outBig = HRECD;H = inBig;break;
			case 3: if(inBig.compareTo(KFIN) == 0){outBig = null;keyctr ++;break;}
			}
			if(outBig!=null)
			{outputLine = outBig.toByteArray();
			out.write(outputLine,0,outputLine.length);}
			if(keyctr ==4) break;
			while(in.available() ==0)
				;
		}
		
	}
	
	/**
	 * @author kasaquan
	 * secure multiplication on cipherA and cipherB
	 * @throws IOException 
	 * @throws CryptoException */
	public static BigInteger[] secureMul(BigInteger[] cipherA, BigInteger[] cipherB,BufferedInputStream in, PrintStream out) throws IOException, CryptoException
	{
		/*varials initial*/
		byte[] inputLine = new byte[20];
		byte[] outputLine;
		BigInteger inBig = BigInteger.ZERO;
		BigInteger outBig = BigInteger.ZERO;
		int bytenum = 0;
		byte[] theInput = null;
		int mctr = 0;
		BigInteger[] smresult = new BigInteger[2];
		
		//add some random to cipherA,cipherB
		BigInteger r1 = new BigInteger(1024,new Random());
		r1 = r1.mod(N.divide(BigInteger.valueOf(4))).add(BigInteger.ONE);
		BigInteger r2 = new BigInteger(1024,new Random());
		r2 = r2.mod(N.divide(BigInteger.valueOf(4))).add(BigInteger.ONE);
		System.out.println("2 randoms chosen: "+ r1+" "+r2);
		//encrypt these 2 randoms
		BigInteger[] rA = scm.encrypt(r1);
		BigInteger[] rB	= scm.encrypt(r2);
		cipherA = scm.homo_add(cipherA, rA);
		cipherB = scm.homo_add(cipherB, rB);
		
		outputLine = MREQ.toByteArray();
		out.write(outputLine,0,outputLine.length);
		sent_overhead = sent_overhead+outputLine.length;
		System.out.println("secureMul request sent!@Main "+MREQ);
		//waiting for inputs
		while(in.available() ==0)
			;
		while(in.available()>0){
			bytenum = in.available();
			receive_overhead = receive_overhead + bytenum;
			//System.out.println(bytenum);
			in.read(inputLine, 0, bytenum);
			theInput = new byte[bytenum]; 
			System.arraycopy(inputLine, 0, theInput, 0, bytenum);
			inBig = new BigInteger(theInput);
			theInput = null; //release
			System.out.println("Recieved:@Main "+ inBig);	
			if (inBig.compareTo(MACK) == 0)
			{
				switch(mctr){
				case 0: outBig =cipherA[0]; mctr ++; break;
				case 1: outBig =cipherA[1]; mctr ++; break;
				case 2: outBig =cipherB[0]; mctr ++; break;
				case 3: outBig =cipherB[1]; mctr ++; break;
				}
			}else{
				if(mctr == 4)
					{smresult[0]=inBig;mctr = 0;outBig = MACK;}
				else
					{smresult[1] = inBig; outBig = null;}
			}
			
			if (outBig != null)
			{
				outputLine = outBig.toByteArray();
				out.write(outputLine,0,outputLine.length);
				sent_overhead = sent_overhead+outputLine.length;
				System.out.println(outBig+" sent!@Main");
			}else break;
			
			while(in.available() ==0)
				;
		}
		System.out.println("[randomized AUAQ] received!@Main");
		// implement here!!
		BigInteger[] rArB = scm.encrypt(r1.multiply(r2).mod(N));
		smresult = scm.homo_minus(smresult, rArB);
		BigInteger[] aUrB = scm.homo_multi(cipherA, r2);
		smresult = scm.homo_minus(smresult, aUrB);
		BigInteger[] aQrA = scm.homo_multi(cipherB, r1);
		smresult = scm.homo_minus(smresult, aQrA);
		
		System.out.println("Secure Multiplication done Once!");
		return smresult;
		
	}
	
	/**
	 * @author kasaquan
	 * proximation divide
	 * @throws IOException 
	 * @throws CryptoException */
	public static BigInteger[] pro_div(BigInteger[] Numerator, BigInteger[] Denominator, BufferedInputStream in, PrintStream out) throws IOException, CryptoException{
		//generate 2 randoms
		BigInteger r1 = new BigInteger(1024,new Random());
		r1 = r1.mod(N.divide(BigInteger.valueOf(4))).add(BigInteger.ONE);
		BigInteger r2 = new BigInteger(1024,new Random());
		r2 = r2.mod(N.divide(BigInteger.valueOf(4))).add(BigInteger.ONE);
		//add randoms to numerator and denominator before sending to proxy
		/**old-version division*/
		//BigInteger[] rN = scm.homo_multi(Numerator, r1);
		//BigInteger[] rD = scm.homo_multi(Denominator, r2.modPow(BigInteger.valueOf(2), N));
		/**new version division*/
		BigInteger[] temp1 = scm.homo_multi(Numerator, BigInteger.valueOf(10));
		BigInteger[] temp2 = scm.homo_multi(Denominator, r1);
		BigInteger[] temp = scm.homo_add(temp1, temp2);
		BigInteger[] rN = scm.homo_multi(temp, r2);
		BigInteger[] rD = scm.homo_multi(Denominator, r2);
		//send randomized rN and rD to proxy server
		byte[] inputLine = new byte[20];
		byte[] outputLine;
		BigInteger inBig = BigInteger.ZERO;
		BigInteger outBig = BigInteger.ZERO;
		int bytenum = 0;
		byte[] theInput = null;
		int dctr = 0;
		BigInteger[] sdresult = new BigInteger[2];
		
		outputLine = DREQ.toByteArray();
		out.write(outputLine,0,outputLine.length);
		sent_overhead = sent_overhead+outputLine.length;
		System.out.println("secureDiv request sent!@Main");
		while(in.available()==0)
			;
		while(in.available()>0){
			bytenum = in.available();
			in.read(inputLine, 0, bytenum);
			receive_overhead = receive_overhead+bytenum;
			theInput = new byte[bytenum]; 
			System.arraycopy(inputLine, 0, theInput, 0, bytenum);
			inBig = new BigInteger(theInput);
			theInput = null; //release
			if (inBig.compareTo(DACK) == 0)
			{
				switch(dctr){
				case 0: outBig =rN[0]; dctr ++; break;
				case 1: outBig =rN[1]; dctr ++; break;
				case 2: outBig =rD[0]; dctr ++; break;
				case 3: outBig =rD[1]; dctr ++; break;
				}
			}else if(dctr == 4)
			{sdresult[0]=inBig;dctr = 0;outBig = DACK;}
			else if(dctr == 0)
			{	sdresult[1] = inBig; 
				System.out.println("Secure div transmission done!@Main");
				outBig = null;
			}
			
			if (outBig != null)
			{
				outputLine = outBig.toByteArray();
				out.write(outputLine,0,outputLine.length);
				sent_overhead = sent_overhead+outputLine.length;
				System.out.println(outBig+" sent@Main");
			}else break;
			
			while(in.available() ==0)
				;
		}
		/**old version*/
		//sdresult is [R] now, and we want to compute [R(r2/r1)]
		//sdresult = scm.homo_multi(sdresult, r1.divide(r2));
		/**new version*/
		sdresult = scm.homo_minus(sdresult, scm.encrypt(r1));
		return sdresult;
	}
}