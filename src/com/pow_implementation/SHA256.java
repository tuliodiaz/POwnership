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


/**
 * SHA256 class
 * This class implements several variation of SHA 256 
 * They are designed to read from an input stream, 
 * to work with long variables and to retrive 
 * intermediate hash values.
 * @author: Tulio Diaz
 * @version: 1.0
 * @see 
*/

public class SHA256 {	
	private static int BLOCK_SIZE=64;//64 bytes = 512 bits
	
	
	public  byte[] hashSHA256FromFile(InputStream iFile, ArrayList<byte[]> IVContainer) throws IOException {
		
	
		byte[] hashed = null, buffer = new byte[BLOCK_SIZE], block;
		int[] K = {
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
		int[] H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
		

		for (int count = iFile.read(buffer); count != -1; count = iFile.read(buffer)) { 
				
			if (count < 64)
				block=padMessage(buffer);
			else
				block=buffer;
				
			int[] words = new int[64];
				
			int a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7], s0, s1, maj, t1, t2, ch;
		
	
			//copy type from 64 byte to 16 int	
			for (int j = 0; j < 16; j++) {
				words[j] = 0;
				for (int k = 0; k < 4; k++) {
					words[j] |= ((block[j * 4 + k] & 0x000000FF) << (24 - k * 8));
				}
			}
		
			for (int j = 16; j < 64; j++) {
				s0 = Integer.rotateRight(words[j-15], 7) ^ Integer.rotateRight(words[j-15], 18) ^ (words[j-15] >>> 3);
				s1 = Integer.rotateRight(words[j-2], 17) ^ Integer.rotateRight(words[j-2], 19) ^ (words[j-2] >>> 10);
				words[j] = words[j-16] + s0 + words[j-7] + s1;
			}
		
			for (int j = 0; j < 64; j++) {
				s0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
				maj = (a & b) ^ (a & c) ^ (b & c);
				t2 = s0 + maj;
				s1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
				ch = (e & f) ^ (~e & g);
				t1 = h + s1 + ch + K[j] + words[j];
		
				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}
		
			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
			H[5] += f;
			H[6] += g;
			H[7] += h;
			
			hashed = new byte[32];
			
			for (int l = 0; l < 8; l++) {
				System.arraycopy(intToBytes(H[l]), 0, hashed, 4*l, 4);
			}
				
			if(IVContainer!=null){
				//System.out.println(bytesToStrint(hashed));
				IVContainer.add(hashed);
			}

		}
		
		return hashed;
	}
	
	public byte[] hashSHA256(long[] message) {

        byte[] hashed = new byte[32];
        long []  block = new long[64],  padded = padMessage(message);
        int[] K = {
                        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        int[] H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        for (int i = 0; i < padded.length / 8; i++) {
                int[] words = new int[64];
                int a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7], s0, s1, maj, t1, t2, ch;

                System.arraycopy(padded, 8 * i, block, 0, 8);
                for (int j = 0; j < 16; j+=2) {
                        words[j] = (int)(block[j/2] >> 32);
                        words[j+1] = (int)(block[j/2] & 0xFFFFFFFF);
                }

                for (int j = 16; j < 64; j++) {
                        s0 = Integer.rotateRight(words[j-15], 7) ^ Integer.rotateRight(words[j-15], 18) ^ (words[j-15] >>> 3);
                        s1 = Integer.rotateRight(words[j-2], 17) ^ Integer.rotateRight(words[j-2], 19) ^ (words[j-2] >>> 10);
                        words[j] = words[j-16] + s0 + words[j-7] + s1;
                }

                for (int j = 0; j < 64; j++) {
                        s0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                        maj = (a & b) ^ (a & c) ^ (b & c);
                        t2 = s0 + maj;
                        s1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                        ch = (e & f) ^ (~e & g);
                        t1 = h + s1 + ch + K[j] + words[j];

                        h = g;
                        g = f;
                        f = e;
                        e = d + t1;
                        d = c;
                        c = b;
                        b = a;
                        a = t1 + t2;
                }

                H[0] += a;
                H[1] += b;
                H[2] += c;
                H[3] += d;
                H[4] += e;
                H[5] += f;
                H[6] += g;
                H[7] += h;
        }

        for (int i = 0; i < 8; i++) {
                System.arraycopy(intToBytes(H[i]), 0, hashed, 4*i, 4);
        }
        
        return hashed;
	}
	
	public byte[] hashSHA256(byte[] message) {
		
        byte[] hashed = new byte[32], block = new byte[64], padded = padMessage(message);
        int[] K = {
                        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        int[] H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        for (int i = 0; i < padded.length / 64; i++) {
                int[] words = new int[64];
                int a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7], s0, s1, maj, t1, t2, ch;

                System.arraycopy(padded, 64 * i, block, 0, 64);
                for (int j = 0; j < 16; j++) {
                        words[j] = 0;
                        for (int k = 0; k < 4; k++) {
                                words[j] |= ((block[j * 4 + k] & 0x000000FF) << (24 - k * 8));
                        }
                }

                for (int j = 16; j < 64; j++) {
                        s0 = Integer.rotateRight(words[j-15], 7) ^ Integer.rotateRight(words[j-15], 18) ^ (words[j-15] >>> 3);
                        s1 = Integer.rotateRight(words[j-2], 17) ^ Integer.rotateRight(words[j-2], 19) ^ (words[j-2] >>> 10);
                        words[j] = words[j-16] + s0 + words[j-7] + s1;
                }

                for (int j = 0; j < 64; j++) {
                        s0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                        maj = (a & b) ^ (a & c) ^ (b & c);
                        t2 = s0 + maj;
                        s1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                        ch = (e & f) ^ (~e & g);
                        t1 = h + s1 + ch + K[j] + words[j];

                        h = g;
                        g = f;
                        f = e;
                        e = d + t1;
                        d = c;
                        c = b;
                        b = a;
                        a = t1 + t2;
                }

                H[0] += a;
                H[1] += b;
                H[2] += c;
                H[3] += d;
                H[4] += e;
                H[5] += f;
                H[6] += g;
                H[7] += h;
        }

        for (int i = 0; i < 8; i++) {
                System.arraycopy(intToBytes(H[i]), 0, hashed, 4*i, 4);
        }

     	
        return hashed;
	}
	
	
	private static byte[] padMessage(byte[] data){
		int origLength = data.length;
		int tailLength = origLength % 64;
		int padLength = 0;
		if(tailLength==0)
			return data;
		
		padLength = 64 - tailLength;
		
		byte[] thePad = new byte[padLength];
		byte[] output = new byte[origLength + padLength];

		System.arraycopy(data, 0, output, 0, origLength);
		System.arraycopy(thePad, 0, output, origLength, thePad.length);
		
		return output;
	}
	
	private static long[] padMessage(long[] data){
		int origLength = data.length;
		int tailLength = origLength % 8;
		int padLength = 0;
		if(tailLength==0)
			return data;
		
		padLength = 8 - tailLength;
		
		long[] thePad = new long[padLength];
		long[] output = new long[origLength + padLength];

		System.arraycopy(data, 0, output, 0, origLength);
		System.arraycopy(thePad, 0, output, origLength, thePad.length);
		
		return output;
	}
	
	public static byte[] intToBytes(int i) {
	    byte[] b = new byte[4];
	    for (int c = 0; c < 4; c++) {
	            b[c] = (byte) ((i >>> (56 - 8 * c)) & 0xff);
	    }
	    return b;
	}
	
	public String bytesToStrint(byte[] bytes){
		StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
          sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
	}
	
	public static String printBites(long l[]){
  		StringBuilder b = new StringBuilder();
  		for(int i=0; i<l.length;i++){
  			String s = Long.toBinaryString(l[i]);
  			b.append("0000000000000000000000000000000000000000000000000000000000000000".substring(s.length())+s);
  		}
  			return b.toString();
  	}
}
