//    Copyright 2015 Tulio Alfredo Diaz Lopez
//
//    This file is part of Proof of ownership protocol.
//
//    Proof of ownership an implementation of the research paper 
//    Proofs of Ownership in Remote Storage Systems by  Shai Halevi, Danny Harnik, 
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

/**
 * Test_app class
 * Main class to test the protocol.
 * @author: Tulio Diaz
 * @version: 1.0
 * @see 
 */

public class Test_app 
{
    public static void main( String[] args ) throws NoSuchAlgorithmException, IOException
    {
    	POwnership p = new POwnership();
    	SHA256 hSHA256 = new SHA256();
    	MerkleTree mt = new MerkleTree();
    	
    	File file =new File("c:\\vehicule-usage.pdf");
    	FileInputStream fis = new FileInputStream(file);
    	
    	System.out.println("Calculating Hash");
    	//SHA256
    	ArrayList<byte[]> iVHash = new ArrayList<byte[]>();

    	byte [] fileHash=hSHA256.hashSHA256FromFile(fis,iVHash);
		
    	System.out.println("File Hash: " + hSHA256.bytesToStrint(fileHash));
    	//InputStream must be reopen
    	fis.close(); 
    	fis =  new FileInputStream(file);
    	
    	//Reduction Phase
    	System.out.println("reducing File");
    	long [] buffer = p.reduceFile(fis, (int)file.length(), iVHash);
    	
    	//Mixing Phase
    	System.out.println("mixing File " + buffer.length);
    	long [] mixedBuffer=p.mixBuffer(buffer, iVHash);
    	
    	//Build Merkle Tree
    	System.out.println("Build Markle Tree..");
    	mt.BuildLeavesFromBuffer(mixedBuffer);
    	System.out.println("Markle Tree root " + hSHA256.bytesToStrint(mt.getRootNode().getHash()) + " height "+ mt.getHeight() + " Num of Nodes: " + mt.Size() + " width: " + mt.getWidth()); 
    	
    	//Extract 3 SiblingPaths
    	MerkleTree mtL1 = mt.getSiblingPath(mt.getNodeById(40));
    	MerkleTree mtL50 = mt.getSiblingPath(mt.getNodeById(50));
    	MerkleTree mtL200 = mt.getSiblingPath(mt.getNodeById(800));
    	
    	//validate Merkle Tree should be done at server 
    	System.out.println("Validating Markle Tree....");
    	MerkleTree vMt = new MerkleTree(); //should be root node loaded from DB
 	
    	//add the SiblingPath to a new Merkle Tree
    	vMt.addSiblingPath(mtL1);
    	vMt.addSiblingPath(mtL50);
    	vMt.addSiblingPath(mtL200);
    	
    	//False Validation
    	/*MerkleNode nFake= new MerkleNode(mt.getNodeById(8666));
    	byte [] b = new byte[32];
    	b[10]=124;		
    	nFake.setHash(b);
    	vMt.addNode(nFake);*/
    	
    	System.out.println("Validation Markle Tree root " + hSHA256.bytesToStrint(vMt.getRootNode().getHash()) + " height "+ vMt.getHeight() + " Num of Nodes: " + vMt.Size()+ " width: " + vMt.getWidth()); 
    	System.out.println("Is Valid? " + vMt.isValid());
    	
    	//System.out.println("finish " + mixedBuffer.length);*/

    }
 
   
  	
}
