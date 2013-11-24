package proxy_server;
/*
 * @kasaquan
 * execute the 2PC secure multiplication*/

import java.net.*;
import java.util.Vector;
import java.io.*;
import java.math.BigInteger;

import crypto_scheme.CryptoException;
import crypto_scheme.Scheme;
import crypto_scheme.KeyGenerator;

public class ProxyProtocol {

	private BigInteger N;
	private BigInteger G;
	private BigInteger H;
	private BigInteger X;
	private Vector<BigInteger> keys = new Vector<BigInteger>(4);
	private BigInteger theOutput = BigInteger.ONE;
	public Scheme scm;
	private KeyGenerator kg = new KeyGenerator();
	
	private static final int IDLE = 0;
	private static final int SENDINGKEY = 1;
	private static final int RECEIVINGMDATA = 3;
	private static final int RECEIVINGDDATE = 4;
	
	private static final BigInteger KREQ = BigInteger.valueOf(255);
	private static final BigInteger NRECD = BigInteger.valueOf(254);
	private static final BigInteger GRECD = BigInteger.valueOf(253);
	private static final BigInteger HRECD = BigInteger.valueOf(252);
	private static final BigInteger KFIN = BigInteger.valueOf(251);
	
	private static final BigInteger MREQ = BigInteger.valueOf(250);
	private static final BigInteger MACK = BigInteger.valueOf(249);
	
	private static final BigInteger DREQ = BigInteger.valueOf(248);
	private static final BigInteger DACK = BigInteger.valueOf(247);
	
	private int state = IDLE;
	private int mctr = 0;
	private int dctr = 0;
	public Vector<BigInteger> mdata = new Vector<BigInteger>(4);
	public BigInteger[] cipherA = new BigInteger[2];
	public BigInteger[] cipherB = new BigInteger[2];
	public BigInteger[] mresult;
	public BigInteger[] dresult;
	
	public BigInteger processInput(BigInteger theInput) throws CryptoException{
		
		if (state  == IDLE)
		{
			if (theInput.compareTo(KREQ)==0)
				{theOutput = N; state = SENDINGKEY;}
			else if (theInput.compareTo(MREQ) == 0)
				{theOutput =MACK; state = RECEIVINGMDATA; mctr = 0; }
			else if (theInput.compareTo(DREQ) == 0)
				{theOutput = DACK; state = RECEIVINGDDATE; dctr = 0;}
		}else if (state == SENDINGKEY)
		{
			if (theInput.compareTo(NRECD)==0)
				theOutput = G;
			else if (theInput.compareTo(GRECD)==0)
				theOutput = H;
			else if (theInput.compareTo(HRECD)==0)
				{state = IDLE; theOutput = KFIN;System.out.println("PublicKeys Sent!Back to IDLE");}
		}else if (state == RECEIVINGMDATA)
		{
			switch(mctr){
			case 0:cipherA[0]=theInput; mctr++; theOutput = MACK; break;
			case 1:cipherA[1]=theInput; mctr++; theOutput = MACK; break;
			case 2:cipherB[0]=theInput; mctr++; theOutput = MACK; break;
			case 3:cipherB[1]=theInput; mresult = scm.secu_multi(cipherA, cipherB);theOutput = mresult[0];mctr++;break;
			case 4:if (theInput.compareTo(MACK) == 0)
					{theOutput = mresult[1];state = IDLE; mctr =0; break;}
			}
		}else if (state == RECEIVINGDDATE)
		{
			switch(dctr){
			case 0:cipherA[0]=theInput; dctr++; theOutput = DACK; break;
			case 1:cipherA[1]=theInput; dctr++; theOutput = DACK; break;
			case 2:cipherB[0]=theInput; dctr++; theOutput = DACK; break;
			case 3:{cipherB[1]=theInput; 
					dresult = scm.secu_div(cipherA, cipherB);
					theOutput = dresult[0];dctr++;break;}
			case 4:if (theInput.compareTo(DACK) == 0)
					{theOutput = dresult[1];state = IDLE; dctr =0; break;}
			}
		}
			
		System.out.println("State: "+ state + " theOutput:" + theOutput);
		return theOutput;
		
	}
	
	
	/**
	 * if you want to generate new keys(public,private), call this function
	 * run this first before processing input*/
	public Vector<BigInteger> generatePublicKeys(){		
		kg.generatePublicKeys();
		N = kg.getN();
		G = kg.getG();
		H = kg.getH();
		X = kg.getX();
		keys.addElement(N);
		keys.addElement(G);
		keys.addElement(H);
		keys.addElement(X);
		scm =  new Scheme(N,G,H,X);		
		return keys;
	}
	
	public void generatePrivateKey(){
		kg.generatePrivateKey();
	}
	
	public void primegen(){
		kg.generatePrimes();
	}
	
}

