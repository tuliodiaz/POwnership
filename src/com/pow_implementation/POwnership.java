//    Copyright 2015 Tulio Alfredo Diaz Lopez
//
//    This file is part of Proof of ownership protocol.
//
//    Proof of ownership an implementation of the Proofs of Ownership 
//    in Remote Storage Systems protocol by  Shai Halevi, Danny Harnik, 
//    Benny Pinkas, and Alexandra Shulman-Peleg available at 
//    https://eprint.iacr.org/2011/207.pdf
//
//    Proof of ownership is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    Proof of ownership is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with Proof of ownership.  If not, see <http://www.gnu.org/licenses/>.

package com.pow_implementation;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Random;

/**
 * POwnership class
 * Implements the main algorithms in the protocol
 * Reduce Phase
 * Mixing Phase
 * Cycle shifting
 * Pseudorandom number generation from 256 bits
 * @author: Tulio Diaz
 * @version: 1.0
 * @see 
*/

public class POwnership {

	private static int MAX_BUFFER_SIZE= 67108864; //bytes = 64MB in packs of 8 bits
	private static int BASE_TYPE=8; //Long 8 bytes
	private static int FILE_BLOCK_SIZE=64; // 64 bytes = 512 bits
	private static int BUFFER_BLOCK_SIZE=8; // 8 long = 64 bytes =  512 bits
	private static int MIX_PHASES=5;


	SHA256 s = new SHA256();
	//reduction phase
	public long[] reduceFile(InputStream iFile, int iFileSize, ArrayList<byte[]> hashIVs) throws IOException{

		int bufferSize=MAX_BUFFER_SIZE/BASE_TYPE;
		
		if((iFileSize/BASE_TYPE)<bufferSize)
			bufferSize=iFileSize/BASE_TYPE;
			
		long [] buffer = new long[bufferSize], block;
		byte [] fileBlock = new byte[FILE_BLOCK_SIZE];
		int [] idx;		
	
		for (int iRead = iFile.read(fileBlock), i=0; iRead != -1; iRead = iFile.read(fileBlock), i++) {
				
			block = bytesToLong(fileBlock);
			
			//1
			idx=indexsFromIV(hashIVs.get(i),bufferSize/BUFFER_BLOCK_SIZE);
			
			//2
			for(int j=0; j<4; j++){
				//3				
				block=cycleShiftBlock(block, j*128);
	
				//4
				for(int x=0;x<BUFFER_BLOCK_SIZE;x++)
					buffer[(idx[j]*BUFFER_BLOCK_SIZE)+x]^=block[x]; //XOr
			}
			
	      	}
		
		return buffer;
		
	}
	
	//mixing phase
	public long[] mixBuffer(long [] buffer, ArrayList<byte[]> hashIVs){

		long [] block = new long[BUFFER_BLOCK_SIZE];
		long [] cBlock;
		int [] idx;
		
		int l = buffer.length/BUFFER_BLOCK_SIZE;
		
		//mix 5 times
		for(int r=0;r<MIX_PHASES;r++){
		
			//run on buffer
			for (int i=0; i<l; i++) {
								
				//1
				System.arraycopy(buffer, BUFFER_BLOCK_SIZE * i, block, 0, BUFFER_BLOCK_SIZE);
			
				idx=indexsFromIV(hashIVs.get(i),l);
				
				for(int j=0; j<4; j++){
					//2				
					cBlock=cycleShiftBlock(block, j*128);	
					
					//4
					for(int x=0;x<BUFFER_BLOCK_SIZE;x++)
						buffer[(idx[j]*BUFFER_BLOCK_SIZE)+x]^=cBlock[x]; //XOr
					
				}
		    }
		}
			
		return buffer;
			
	}
	
	
	//challenge leave 
	public int [] createChallenge(int numOfLeaves, int challengeSize){
	
		int cLeaves[] = new int[challengeSize];
	
		Random rand = new Random();
		  
		for(int i=0; i<challengeSize;i++)
		 	cLeaves[i] = rand.nextInt(numOfLeaves)+1;
				
		return cLeaves;
	}

	//calculate the index from IV
	private int [] indexsFromIV(byte [] iv,  int maxValue){
		int bits, index[] = new int[4], subIV[] = new int[4];
		
		subIV[0]=(iv[0] & 0xff)|((iv[1] & 0xff)<< 8)|((iv[2] & 0xf)<< 16); //20 bits Index 1 first 64 bits
		subIV[1]=(iv[8] & 0xff)|((iv[9] & 0xff)<< 8)|((iv[10] & 0xf)<< 16); //20 bits Index 2 from 64 to 128
		subIV[2]=(iv[16] & 0xff)|((iv[17] & 0xff)<< 8)|((iv[18] & 0xf)<< 16); //20 bits Index 3
		subIV[3]=(iv[24] & 0xff)|((iv[25] & 0xff)<< 8)|((iv[26] & 0xf)<< 16); //20 bits Index 4
		
		// How many bits are in maxValue? 360 (8(255) + 6(64) + 5(32) + 3(8) + 1)
		while((bits = (int) Math.pow(2, ((int) (Math.log(maxValue)/Math.log(2)))))>0){
			//XOR generate more random
			subIV[0]^=subIV[1];
			subIV[1]^=subIV[2];
			subIV[2]^=subIV[3];
			subIV[3]^=subIV[0];
			subIV[1]^=subIV[0];
			subIV[2]^=subIV[1];
			subIV[3]^=subIV[2];
			subIV[0]^=subIV[3];
			
			//create index by sum of bits
			index[0] += (subIV[0] & (bits-1));
			index[1] += (subIV[1] & (bits-1));
			index[2] += (subIV[2] & (bits-1));
			index[3] += (subIV[3] & (bits-1));
			
			maxValue -= bits;
		}
			
		return index;
	}
	
	//buffer cycle shift 0, 128, 256, 384
  	public static  long[] cycleShiftBlock(long[] in, int step) {
  		
  		int len = in.length-1, offset=step, pos, idx;
  		
  		if(step<=0)
  			return in;
  		
  		long[] out = new long[len+1];
  		
  		for (int i=0; i<=len; i++) {
  			long hBits = 0, lBits=0;
  			idx=offset/64;	
  			
  			if((pos=step%64)!=0){
  				lBits=in[i] >> pos;
  				hBits=in[i==0?len:i-1] << (64-pos);
  				out[idx]=hBits+lBits+out[idx]; 
  			}else
  				out[idx]=in[i];
 	 
  			if((offset+=64)>=(in.length*64))
  				offset=0;
  	  	 }
  	     return out;
  	}

	public static long [] bytesToLong(byte[] b) {
	    long [] result = new long[b.length/BASE_TYPE];
	    for (int i = 0; i<b.length/BASE_TYPE; i+=BASE_TYPE) {
	        result [i] = ((((long) b[i+7]) << 56) | (((long) b[i+6] & 0xff) << 48) | (((long) b[i+5] & 0xff) << 40)
		            | (((long) b[i+4] & 0xff) << 32) | (((long) b[i+3] & 0xff) << 24) | (((long) b[i+2] & 0xff) << 16)
		            | (((long) b[i+1] & 0xff) << 8) | (((long) b[i+0] & 0xff)));
	    }
	    return result;
	}
}
