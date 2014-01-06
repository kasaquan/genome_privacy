package proxy_server;
/*
 * @kasaquan
 * execute the 2PC secure multiplication*/

import java.net.*;
import java.util.ArrayList;
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
	private BigInteger X1;
	private BigInteger X2;
	private Vector<BigInteger> keys = new Vector<BigInteger>(4);
	private BigInteger theOutput = BigInteger.ONE;
	public Scheme scm;
	private KeyGenerator kg = new KeyGenerator();
	
	private static final int IDLE = 0;
	private static final int SENDINGKEY = 1;
	private static final int RECEIVINGMDATA = 3;
	private static final int RECEIVINGDDATE = 4;
	private static final int RECEIVINGZDATA = 5; //receiving comparison data Z
	private static final int COMPARING = 6;//doing comparison
	private static final int SENDINGPKEY = 7; //sending private keys to SPU and MP
	
	private static final BigInteger KREQ = BigInteger.valueOf(255);
	private static final BigInteger NRECD = BigInteger.valueOf(254);
	private static final BigInteger GRECD = BigInteger.valueOf(253);
	private static final BigInteger HRECD = BigInteger.valueOf(252);
	private static final BigInteger KFIN = BigInteger.valueOf(251);
	
	private static final BigInteger MREQ = BigInteger.valueOf(250);
	private static final BigInteger MACK = BigInteger.valueOf(249);
	
	private static final BigInteger DREQ = BigInteger.valueOf(248);
	private static final BigInteger DACK = BigInteger.valueOf(247);
	
	private static final BigInteger CompInit = BigInteger.valueOf(246);
    private static final BigInteger CompRequest = BigInteger.valueOf(245);
    private static final BigInteger CpPrivateKey = BigInteger.valueOf(244);
	
	
	private int state = IDLE;
	private int mctr = 0;
	private int dctr = 0;
	private int zctr = 0;
	private int zictr = 0;
	boolean ziflag = true;
	public Vector<BigInteger> mdata = new Vector<BigInteger>(4);
	public BigInteger[] cipherA = new BigInteger[2];
	public BigInteger[] cipherB = new BigInteger[2];
	public BigInteger[] mresult;
	public BigInteger[] dresult;
	public BigInteger[] encrypted_Z = new BigInteger[2];
	public BigInteger Z;
	public ArrayList<BigInteger> zi = new ArrayList<BigInteger>();
	public ArrayList<BigInteger[]> cipher_zi = new ArrayList<BigInteger[]>();
	public int users = 0;
	public int n=0; // comparison iterations
	
	public BigInteger processInput(BigInteger theInput) throws CryptoException{
		
		if (state  == IDLE)
		{
			if (theInput.compareTo(KREQ)==0)
				{theOutput = N; state = SENDINGKEY;}
			else if (theInput.compareTo(MREQ) == 0)
				{theOutput =MACK; state = RECEIVINGMDATA; mctr = 0; }
			else if (theInput.compareTo(DREQ) == 0)
				{theOutput = DACK; state = RECEIVINGDDATE; dctr = 0;}
			else if (theInput.compareTo(CompInit) == 0)
				{theOutput = BigInteger.ONE; state = RECEIVINGZDATA; zctr = 0; }
			else if (theInput.compareTo(CpPrivateKey) == 0)
				{theOutput = X1; state =SENDINGPKEY;}
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
		}else if (state == RECEIVINGZDATA)
		{
			switch(zctr){
			case 0: encrypted_Z[0]=theInput; zctr++; theOutput=BigInteger.ONE;break;
			case 1: encrypted_Z[1]=theInput; zctr++; theOutput=BigInteger.ONE;break;
			case 2: {
				users=theInput.intValue(); 
				if(users>0){
					state=COMPARING; 
					theOutput=CompRequest; 
					//decrypt Z
					Z = scm.decrypt(encrypted_Z);
					//unpack Z into n compartments n = users;
					n = (int)Math.ceil(Z.bitLength()/this.users);
					BigInteger[] tempz = this.seperation(Z, n);
					for(int i=0;i<n;i++){
						zi.add(tempz[i]);
					    cipher_zi.add(scm.encrypt(tempz[i]));
					}
					tempz = null;
				}
				else
					{state=IDLE; theOutput = BigInteger.ZERO;}
				zictr = 0;
				zctr++;break;}
			case 3:{
				if(zictr<this.users){
					if(ziflag)
						theOutput = cipher_zi.get(zictr)[0];
					else{
						theOutput = cipher_zi.get(zictr)[1];
						zictr++;
					}
					ziflag = !ziflag;
				}
				if(zictr == this.users)
					state = IDLE;
			}
			}
		}else if(state == SENDINGPKEY)
		{
			theOutput = X2;
			state = IDLE;
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
		X1 = kg.getX1();
		X2 = kg.getX2();
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
	
	/**@author kasaquan
	 * function of black box
	 * Separate different compartments
	 * return array seperated_A = {A(i)}*/
	public BigInteger[] seperation(BigInteger packedA, int clength){
		BigInteger A = packedA;
		int iterations = (int)(Math.ceil(A.bitLength()/clength));
		BigInteger[] seperated_A = new BigInteger[iterations];
		BigInteger[] temp = new BigInteger[2];
		
		// m = 2^clength
		BigInteger m = BigInteger.ONE;
		m = m.shiftLeft(clength);
		
		//calculate compartment contents
		for(int i=0; i<iterations; i++){
			 temp = A.divideAndRemainder(m);
			 A = temp[0];
			 seperated_A[i]=temp[1];
		}
		return seperated_A;
	}
	
}

