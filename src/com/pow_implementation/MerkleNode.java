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

import java.util.Arrays;

/**
 * MerkleNode class
 * An object MerkleNode represent a node 
 * of the Merkle-Tree. Holding the hash value and
 * ID of parents and child. Such node can be leaf, 
 * tree-node or root node.
 * @author: Tulio Diaz
 * @version: 1.0
 * @see 
 */


public class MerkleNode {
	private byte [] hash; 
	private NodeType type;
	private int id, pId, lChildId, rChildId;

	public MerkleNode(byte [] hashNode,int idNode, int parentId, int leftChildId,  int rightChildId, NodeType type ){
		setId(idNode);
		setHash(hashNode);
		setLeftChild(leftChildId);
		setRightChild(rightChildId);
		setParent(parentId);	
		this.type = type;
	}
	
	public MerkleNode(MerkleNode sNode) {
		
		this(sNode.hash,sNode.getId(),sNode.getParent(),sNode.getLeftChild(), sNode.getRightChild(), sNode.getType());
		
	}
	
	public MerkleNode() {
	}
	
	public byte[] getHash() {
		return hash;
	}
	
	public void setHash(byte[] hashValue) {
		this.hash=CopyIfNotNull(hashValue);
	}
	
	public int getLeftChild() {
		return lChildId;
	}
	
	public void setLeftChild(int idNode) {
		this.lChildId = idNode;
	}
	
	public int getRightChild() {
		return rChildId;
	}
	
	public void setRightChild(int idNode) {
		this.rChildId=idNode;
	}
	
	public int getParent() {
		return pId;
	}
	
	public void setParent(int idNode) {
		this.pId = idNode;
	}
	
	public NodeType getType() {
		return type;
	}
	
	public void setType(NodeType type) {
		this.type=type;	
	}
	
	public int getId() {
		return id;
	}
	
	public void setId(int id) {
		this.id = id;
	}
	
	private byte[] CopyIfNotNull(byte[] hashValue) {
		byte [] tmpHash=null;
		
		if(hashValue!=null){
			tmpHash = new byte[hashValue.length];
			System.arraycopy(hashValue, 0, tmpHash, 0, hashValue.length);
		}

		return tmpHash;
	}
	
	@Override
    public boolean equals(Object other)
    {
        if (!(other instanceof MerkleNode))
        {
            return false;
        }
        return  Arrays.equals(hash, ((MerkleNode)other).getHash())&&id==((MerkleNode)other).getId();
    }

    @Override
    public int hashCode()
    {
    	return Arrays.hashCode(hash);
    }
	
   public enum NodeType {
   	 ROOT, TNODE, LEAF;  
   }


}


