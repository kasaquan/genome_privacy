package main_server;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Random;
import java.util.Vector;
import java.math.BigInteger;

import crypto_scheme.*;


public class MainServer {
	/**key generation relevant states*/
	private static final BigInteger KREQ = BigInteger.valueOf(255);
    private static final BigInteger NRECD = BigInteger.valueOf(254);
    private static final BigInteger GRECD = BigInteger.valueOf(253);
    private static final BigInteger HRECD = BigInteger.valueOf(252);
    private static final BigInteger KFIN = BigInteger.valueOf(251);
    /**secure multiplication relevant states*/
    private static final BigInteger MREQ = BigInteger.valueOf(250);
    private static final BigInteger MACK = BigInteger.valueOf(249);
    /**comparison protocol relevant states*/
    private static final BigInteger CompInit = BigInteger.valueOf(246);
    private static final BigInteger CompRequest = BigInteger.valueOf(245);
    private static final BigInteger CpPrivateKey = BigInteger.valueOf(244);
    
    /**functional variables*/
    public static BigInteger N;
    public static BigInteger G;
    public static BigInteger H;
    private static BigInteger X1,X2;
    public static Vector<BigInteger> keys = new Vector<BigInteger>(3);
    public static Scheme scm;
    public static int l;
    /**changeable parameters*/
    public static final int users = 200; //number of users
    public static final int items = 50;  //number of items
    public static final int kappa = 40; // security parameter 40 bits
    
	
	public static void main(String[] args) throws IOException, CryptoException{
        
        Socket proxySocket = null;
        PrintStream out = null;
        BufferedInputStream in = null;
        
        try{
                proxySocket = new Socket("localhost",2223);
                out = new PrintStream(proxySocket.getOutputStream(),true);
                in = new BufferedInputStream (proxySocket.getInputStream());
        }catch (UnknownHostException e){
                System.err.println("Don't know about the host");
                System.exit(1);
        }catch (IOException e){
                System.err.println("Couldn't get I/O for the connection");
                System.exit(1);
        }
        
        System.out.println("MainServer: connection setup!");
        
        keyRequest(in, out);//request key generation
        scm = new Scheme(N, G, H); // new encryption scheme generated
        
        /**random user data generation*/
        int[][] data = new int[200][50]; // raw,200 users and 50 densely rated items
        BigInteger[][][] data_e = new BigInteger[users][items][2]; // paillier encrypted data
        Random random = new Random();
        for(int i=0; i<data.length; i++)
        	for(int j=0; j<data[0].length; j++)
        	{
        		data[i][j] = random.nextInt(4);
        		data_e[i][j] = scm.encrypt(BigInteger.valueOf(data[i][j]));
        	}
        
        BigInteger[][] V_AC = datapacking(data_e,0);
        System.out.print("datapacking for user A=0 completed.");
        
        BigInteger[] D = packed_sim(V_AC,data_e[0],in,out); // [sim ac]
        
        // the output of comparison includes [ri],[zi] and [carry_i]
        ArrayList<BigInteger[][]> results = comparison(D,in,out);
        
        BigInteger[][] du_sim = derand_unpack_sim(results);
        System.out.print("sim A completed!");
        
        
	}
	
	/**
     * @author kasaquan
     * keyRequest function to get public keys from proxy server*/
	public static void keyRequest(BufferedInputStream in, PrintStream out) throws IOException{
        /*no return paras, because N,G,H are static
         * variables initial*/
        byte[] outputLine;
        byte[] inputLine = new byte[20];// to be modified, too small
        byte[] theInput = null;
        int bytenum = 0;
        BigInteger inBig = BigInteger.ZERO;
        BigInteger outBig = BigInteger.ZERO;
        int keyctr  = 0;
        
        /*sending key request*/
        outputLine = KREQ.toByteArray();
        out.write(outputLine,0,outputLine.length);
        System.out.println("MainServer: keyRequest sent!");
        
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
                case 0:        keyctr ++; outBig = NRECD;N = inBig;break;
                case 1:        keyctr ++; outBig = GRECD;G = inBig;break;
                case 2:        keyctr ++; outBig = HRECD;H = inBig;break;
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
    public static BigInteger[] secureMul(BigInteger[] cipherA, BigInteger[] cipherB,
BufferedInputStream in, PrintStream out) throws IOException, CryptoException
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
            BigInteger[] rB        = scm.encrypt(r2);
            cipherA = scm.homo_add(cipherA, rA);
            cipherB = scm.homo_add(cipherB, rB);
            
            outputLine = MREQ.toByteArray();
            out.write(outputLine,0,outputLine.length);
           // sent_overhead = sent_overhead+outputLine.length;
            System.out.println("secureMul request sent!@Main "+MREQ);
            //waiting for inputs
            while(in.available() ==0)
                    ;
            while(in.available()>0){
                    bytenum = in.available();
                    //receive_overhead = receive_overhead + bytenum;
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
                            //sent_overhead = sent_overhead+outputLine.length;
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
	
	/**function of packing each user's encrypted info
	 * @author kasaquan
	 * @throws CryptoException 
	 * used for generating recommendation on parsely rated items
	 * will not be used in near future*/
	public static BigInteger[] userpacking(BigInteger[][] data_ie) throws CryptoException{
		BigInteger temp1;
		BigInteger[] temp2;
		BigInteger[] data_ipe = scm.encrypt(BigInteger.ZERO);
		// para modification here: the space for carry
		//2^4
		BigInteger space = BigInteger.valueOf(4);
		
		for(int j = 0; j<data_ie.length; j++ ){
			temp1 = BigInteger.valueOf(2).modPow(space.multiply(BigInteger.valueOf(j)), N);
			//[2^cj]
			temp2 = scm.homo_multi(data_ie[j], temp1);//[v*2^cj]
			data_ipe = scm.homo_add(data_ipe, temp2);
		}
		return data_ipe;
	}
	
	/**@author kasaquan
	 * not black box function
	 * compute similarity between A and all other users
	 * results packed in one cipher text
	 * To-do: nomalization stuff
	 * @throws CryptoException 
	 * @throws IOException */
	public static BigInteger[] packed_sim(BigInteger[][] V_AC, BigInteger[][]data_A,
			BufferedInputStream in, PrintStream out) throws CryptoException, IOException{
		BigInteger[] packed_sim_A = scm.encrypt(BigInteger.ZERO);
		for(int j=0; j<data_A.length; j++)
			packed_sim_A = scm.homo_add(packed_sim_A, MainServer.secureMul(V_AC[j], data_A[j], in, out));
		return packed_sim_A;
	}
	
	/**@author kasaquan
	 * black box 1
	 * packing user data for computing similarity
	 * input: the index of user whose similarity needs to be computed
	 * input: element-wise encrypted data of all users 
	 * @throws CryptoException */
	public static BigInteger[][] datapacking(BigInteger[][][] data_e, int A) throws CryptoException{
		BigInteger[][] V_AC = new BigInteger[items][2];
		BigInteger temp1;
		BigInteger[] temp2;
		int k;
		//compartment size, para to be modified here
		BigInteger space = BigInteger.valueOf((long) (4+Math.ceil(Math.log(items)/Math.log(2))+2));//2k+log(times)+2
		
		for(int j=0; j<V_AC.length;j++){
			V_AC[j]=scm.encrypt(BigInteger.ZERO);
			for(int i=0; i<data_e.length; i++)
			{
				if(i<A){
					k = i;
					temp1 = BigInteger.valueOf(2).modPow(space.multiply(BigInteger.valueOf(k)), N);
					temp1 = temp1.add(temp1);
					temp2 = scm.homo_multi(data_e[i][j], temp1);
					V_AC[j] = scm.homo_add(temp2, V_AC[j]);
				}
				else if(i>A){
					k = i-1;
					temp1 = BigInteger.valueOf(2).modPow(space.multiply(BigInteger.valueOf(k)), N);
					temp1 = temp1.add(temp1);
					temp2 = scm.homo_multi(data_e[i][j], temp1);
					V_AC[j] = scm.homo_add(temp2, V_AC[j]);
				}
			}
		}
		return V_AC;
	}
	
	/**@author kasaquan
	 * function of black box 2
	 * add random onto packed sim of A before sending it to proxy server for parsing
	 * @throws CryptoException */
	public static ArrayList rand_sim(BigInteger[] sim_A) throws CryptoException{
		ArrayList results = new ArrayList();
		
		BigInteger[] rand_sim_A = new BigInteger[2];
		
		//calculate the bit length of packed sim_A=(2k+logR+2)N
		l = (int)(4+Math.ceil(Math.log(items)/Math.log(2))+2);
		int sim_bitlength = l*users;
		
		//generate random number of length(sim_A)+k
		BigInteger rand =new BigInteger(sim_bitlength+kappa,new Random());
		
		//add encrypted rand onto encrypted sim_A
		rand_sim_A = scm.homo_add(sim_A, scm.encrypt(rand));
		
		
		//compute r mod 2^sim_biglength
		int k;
		do{
			k = rand.bitLength();
			rand.clearBit(k);
		}
		while(k>sim_bitlength+1);
		
		results.add(rand_sim_A);
		results.add(rand);
		results.add(sim_bitlength);
		return results;
	}
	/**@author kasaquan
	 * used in black box 2
	 * Separate different compartments
	 * return array seperated_A = {A(i)}*/
	public static BigInteger[] seperation(BigInteger packedA, int clength){
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
	
	/**@author kasaquan
	 * comparison protocol
	 * @throws IOException 
	 * @throws CryptoException */
	public static ArrayList comparison(BigInteger[] D, 
			BufferedInputStream in, PrintStream out) throws IOException, CryptoException{
		
		ArrayList<BigInteger[][]> results = new ArrayList<BigInteger[][]>();
		
		ArrayList arrayZ = rand_sim(D);
		BigInteger[] Z = (BigInteger[]) arrayZ.get(0);
		BigInteger rand = (BigInteger) arrayZ.get(1);
		int sim_bitlength = (int) arrayZ.get(2);
		
		
		//seperate r into r(i)
		BigInteger[] ri = seperation(rand, l);
		BigInteger[][] cipher_ri = new BigInteger[ri.length][2];
		for(int i=0; i<ri.length; i++)
			cipher_ri[i] = scm.encrypt(ri[i]);
		BigInteger[][] cipher_zi = new BigInteger[ri.length][2];
		
		
		/*communication vals initial*/
        byte[] inputLine = new byte[50];
        byte[] outputLine;
        BigInteger inBig = BigInteger.ZERO;
        BigInteger outBig = BigInteger.ZERO;
        int bytenum = 0;
        byte[] theInput = null;
        
        
        //send comparison initialization request to proxy server
        outputLine = CompInit.toByteArray();
        out.write(outputLine,0,outputLine.length);
        System.out.println("MainServer:comparison initializaiton request sent! ");
        
      //transfer [z] and number of users to proxyserver
        int cctr = 0;
        int zctr = 0;
        boolean zflag = true;
        while(in.available() ==0)
                ;
        while(in.available()>0){
                bytenum = in.available();
                //receive_overhead = receive_overhead + bytenum;
                in.read(inputLine, 0, bytenum);
                theInput = new byte[bytenum]; 
                System.arraycopy(inputLine, 0, theInput, 0, bytenum);
                inBig = new BigInteger(theInput);
                theInput = null; //release
                System.out.println("Recieved:@Main "+ inBig); 
                //then send Z to proxy server
                if (inBig.compareTo(BigInteger.ONE) == 0)
                {
                        switch(cctr){
                        case 0: outBig =Z[0]; cctr ++; break;
                        case 1: outBig =Z[1]; cctr ++; break;
                        case 2: outBig =BigInteger.valueOf(users); cctr ++; break;
                        case 3: outBig =CompRequest; cctr ++; break;
                        }
                }else if (inBig.compareTo(CompRequest) ==0 ){
                	outBig = BigInteger.ONE;
                }
                else if(inBig.compareTo(BigInteger.ZERO) == 0)
                	break;
                else{
                	if(zctr<users){
                		if(zflag)
                    		cipher_zi[zctr][0]=inBig;
                    	else{
                    		cipher_zi[zctr][1]=inBig;
                    		zctr++;
                    	}
                		zflag = !zflag;
                    	outBig = BigInteger.ONE;
                	}
                	else
                		outBig = null;
                }
                if (outBig != null)
                {
                        outputLine = outBig.toByteArray();
                        out.write(outputLine,0,outputLine.length);
                        //sent_overhead = sent_overhead+outputLine.length;
                        System.out.println(outBig+" sent!@Main");
                }else break;
                
                while(in.available() ==0)
                        ;
        }
        
        //suppose now we have [ri] and [zi]
        //we make use of the comparison protocol to compute [t]
        /**@author kasaquan
         * first get private keys for MU and SPU*/
        BigInteger[] pbKey = {N,G,H};
        outputLine = CpPrivateKey.toByteArray();
        out.write(outputLine,0,outputLine.length);
        int uctr = 0;
        while(in.available() ==0)
            ;
        while(in.available()>0){
            bytenum = in.available();
            //receive_overhead = receive_overhead + bytenum;
            in.read(inputLine, 0, bytenum);
            theInput = new byte[bytenum]; 
            System.arraycopy(inputLine, 0, theInput, 0, bytenum);
            inBig = new BigInteger(theInput);
            theInput = null; //release
            System.out.println("Recieved:@Main "+ inBig); 
            //then send Z to proxy server
            switch(uctr){
            case 0: X1 = inBig; outBig =BigInteger.ONE; uctr ++; break;
            case 1: X2 = inBig; outBig =null; uctr ++; break;
            }
            if (outBig != null)
            {
                    outputLine = outBig.toByteArray();
                    out.write(outputLine,0,outputLine.length);
                    //sent_overhead = sent_overhead+outputLine.length;
                    System.out.println(outBig+" sent!@Main");
            }else break;
            
            while(in.available() ==0)
                    ;
        }
        
        /**@author kasaquan
         * initialization of MU and SPU*/
        MU mu = new MU(X1,pbKey);
        SPU spu = new SPU(X2,pbKey);
        spu.setMu(mu);
        
        BigInteger[][] cipher_carry = new BigInteger[users][2];
        for(int i=0; i<users; i++)
        	 cipher_carry[i]= spu.compareEncryptedValues(cipher_ri[i], cipher_zi[i]);
        
        // r,z,carry
        BigInteger[][] temp = new BigInteger[3][2];
        for(int i=0; i<users; i++){
        	temp[0] = cipher_ri[i];
        	temp[1] = cipher_zi[i];
        	temp[2] = cipher_carry[i];
        	results.add(temp);
        }
        temp = null; // release
        return results;
	}
	
	/**@author kasaquan
	 * make use of [zi],[ri],[carry_i] to get sim_i 
	 * derandomization of unpacked sim
	 * to-do: reduce one time of minus when carry_i is zero
	 * @throws CryptoException */
	public static BigInteger[][] derand_unpack_sim(ArrayList A) throws CryptoException{
		BigInteger[][] du_sim = new BigInteger[users][2];
		BigInteger[][] temp = new BigInteger[3][2];
		for(int i=0; i<users; i++){
			temp = (BigInteger[][]) A.get(i);
			du_sim[i] = scm.homo_minus(scm.homo_minus(temp[1], temp[0]), temp[2]);
		}
		return du_sim;
	}
	
}

