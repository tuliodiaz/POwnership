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
import java.util.HashMap;
import com.pow_implementation.MerkleNode.NodeType;

/**
 * MerkleTree class
 * Support Binary Tree operations build from a buffer of bytes
 * or reconstructed from other tree. The object perform validation
 * using SHA256. 
 * @author: Tulio Diaz
 * @version: 1.0
 * @see 
 */


public class MerkleTree {
	private static int BUFFER_BLOCK_SIZE=8;//64 bytes = 512 bits
	private SHA256 s = new SHA256();
	private int height=0, width=0;
	
	private  HashMap<Integer, MerkleNode> tNodes = new HashMap<Integer, MerkleNode>();
	
	private MerkleNode root;
	
	public MerkleTree(){}
	
	public MerkleTree(byte [] hashRoot) {
		if(hashRoot!=null)
			setRootNode(new MerkleNode(hashRoot,0, 0, 0, 0, MerkleNode.NodeType.ROOT));
	}
	
	public MerkleTree(long [] buffer){
		this.BuildLeavesFromBuffer(buffer);
	}
	
	public void BuildLeavesFromBuffer(long [] buffer){

		long [] block = new long[BUFFER_BLOCK_SIZE]; //512bits
		MerkleNode node=null; 
		
		//First Step build leaves from buffer - level 1
		for(int i=0; i<buffer.length/BUFFER_BLOCK_SIZE;i++){
			
			System.arraycopy(buffer, i*BUFFER_BLOCK_SIZE, block, 0, BUFFER_BLOCK_SIZE);
						
			node = new MerkleNode(s.hashSHA256(block), 0,0,0,0, MerkleNode.NodeType.LEAF);
			
			this.addNode(node);
			
		}
		
		//add empty node if unbalanced tree
		if(tNodes.size()%2!=0) 	
			BuildParentFromChildren(node, getEmptyNode(MerkleNode.NodeType.LEAF));	
		
		height=1;
		width=tNodes.size();
		
		int tNodeMaxIdx = tNodes.size();
		int cLevelSize=tNodeMaxIdx;
		
		//Second Step build tree nodes from leaves (bottom - up)
		for(int i=1; i<tNodeMaxIdx;i+=2){
			
			MerkleNode n = BuildParentFromChildren(getNodeById(i), getNodeById(i+1));
			
			tNodeMaxIdx++;
			
			if(i+1+(cLevelSize/2)>=tNodeMaxIdx){

				height++; //new level
				
				cLevelSize = tNodeMaxIdx - (i+1);
									
				if(cLevelSize==1){ //last level
					this.setRootNode(n);
					getNodeById(n.getLeftChild()).setParent(0);
					getNodeById(n.getRightChild()).setParent(0);
				}
				else //add empty node if unbalanced tree
					if(cLevelSize>2&&(cLevelSize%2)!=0){
						this.addNode(getEmptyNode(MerkleNode.NodeType.TNODE));
						tNodeMaxIdx++;
						cLevelSize++;
				}
			}
		}
		
	}

	private MerkleNode BuildParentFromChildren(MerkleNode leftNode, MerkleNode rightNode) {
		//add tree node
		MerkleNode n = new MerkleNode(getHashFromNodes(leftNode, rightNode),0,0,leftNode.getId(),rightNode.getId(), MerkleNode.NodeType.TNODE);
		
		addNode(n);
		
		//set children's parent
		leftNode.setParent(n.getId());
		rightNode.setParent(n.getId());
		
		return n;
	}

	public void addNode(MerkleNode node) {	
		
		if(node.getType() == MerkleNode.NodeType.ROOT)
			node.setId(0);
		else 
			if(node.getId()==0)
				node.setId(tNodes.size()>0?tNodes.size()+1:1);
		
		tNodes.put(node.getId(), node);
	}
	
	public void removeNode(MerkleNode node) {
			tNodes.remove(node.getId());
	}
	
	public boolean addSiblingPath(MerkleTree MT){
		
		if(this.getRootNode()==null)
			this.setRootNode(new MerkleNode(MT.getRootNode()));
		else
			if(!this.getRootNode().equals(MT.getRootNode()))
				return false;
		
		return addChildNodes(MT,this, MT.getRootNode());
	}
	
	private boolean addChildNodes(MerkleTree sMT, MerkleTree fMT,MerkleNode sNode){
		
		MerkleNode fNode = fMT.getNodeById(sNode.getId());
		
		if(fNode!=null){
			if(fNode.equals(sNode)==false)
				return false;
		}else
			fMT.addNode(new MerkleNode(sNode));
		
		if(sNode.getLeftChild()!=0){
			
			MerkleNode leftNode=sMT.getNodeById(sNode.getLeftChild());
		
			if(leftNode!=null)
				if(!addChildNodes(sMT, fMT, leftNode))
					return false;
		}
		
		if(sNode.getRightChild()!=0){
			
			MerkleNode rightNode=sMT.getNodeById(sNode.getRightChild());
		
			if(rightNode!=null)
				if(!addChildNodes(sMT, fMT, rightNode))
					return false;
		}
			
		return true;
	}
	
	public boolean isValid(){
		boolean ret = validateSiblings(root, root.getLeftChild(), root.getRightChild());
		return ret;
	}
	
	private boolean validateSiblings(MerkleNode pNode, int leftHash, int righHash){
		
		MerkleNode lNode = getNodeById(leftHash);
		MerkleNode rNode = getNodeById(righHash);
			
		if(rNode!=null)
			if(rNode.getRightChild()!=0 && rNode.getLeftChild()!=0)
				if(!validateSiblings(rNode, rNode.getLeftChild(), rNode.getRightChild()))
					return false;
		
		if(lNode!=null)
			if(lNode.getRightChild()!=0 && lNode.getLeftChild()!=0)
				if(!validateSiblings(lNode, lNode.getLeftChild(), lNode.getRightChild()))
					return false;
		
		if(rNode!=null && lNode!=null){
			byte [] cHash=getHashFromNodes( lNode , rNode );
			boolean eq = Arrays.equals(pNode.getHash(), cHash);
			if(!eq)
				System.out.println("Comparation error Hash:" + s.bytesToStrint(pNode.getHash()) + " Calculated: " + s.bytesToStrint(cHash)  + " LeftNode: " + s.bytesToStrint(lNode.getHash())  + " RightNode: " + s.bytesToStrint(rNode.getHash()));
			return eq;
		}
		
		return true;
	}

/*	public MerkleNode getNodeByHash(byte[] hashNode) {
		for(HashMap.Entry<Integer, MerkleNode> entry: tNodes.entrySet())
			if(Arrays.equals(entry.getValue().getHash(),hashNode))
				return entry.getValue();
		
		return null; 
	}*/
	
	public MerkleNode getNodeById(int id) {
		return tNodes.get(id); 
	}

	public MerkleTree getSiblingPath(MerkleNode leaf){
		
		MerkleTree MT = new MerkleTree();
	
		MT.addNode(new MerkleNode(leaf));
			
		while(leaf.getType()!=MerkleNode.NodeType.ROOT){
			
			MerkleNode parent=this.getNodeById(leaf.getParent());
				
			if(parent.getLeftChild()==leaf.getId())
				MT.addNode(new MerkleNode(getNodeById(parent.getRightChild())));
			else
				MT.addNode(new MerkleNode(getNodeById(parent.getLeftChild())));
			
			MT.addNode(parent);
			
			leaf=parent;
		}
		
		MT.setRootNode(leaf);
		
		return MT;
	}
	
	private byte[] getHashFromNodes(MerkleNode lNode , MerkleNode rNode) {
		
		byte [] cHash = new byte [64];
		
		//if node is null hash with 0 bits.
		if(lNode.getHash()!=null)
			System.arraycopy(lNode.getHash(), 0, cHash, 0, 32);
		
		if(rNode.getHash()!=null)
			System.arraycopy(rNode.getHash(), 0, cHash, 32, 32);
		
		return s.hashSHA256(cHash);
	}
	
	public MerkleNode getRootNode(){
		if(root==null)
			root=getNodeById(0);
		return root;
	}
	
	public void setRootNode(MerkleNode nodeRoot){
		nodeRoot.setType(MerkleNode.NodeType.ROOT);
		this.removeNode(nodeRoot);
		this.addNode(nodeRoot);
		this.root=nodeRoot;
	}
	
	public int getHeight() {
		if(height==0 && root!=null)
			return computeHeight(root);
		return height;
	}
	
	private int computeHeight(MerkleNode node){
		int lheight=0, rheight=0;
		if (node == null)
	        return 0;
	    else
	    {
	        if(node.getLeftChild()!=0)
	        	lheight = computeHeight(getNodeById(node.getLeftChild()));
	        if(node.getRightChild()!=0)
	        	rheight = computeHeight(getNodeById(node.getRightChild()));
	 
	        /* use the larger one */
	        if (lheight > rheight)
	            return (lheight + 1);
	        else
	            return (rheight + 1);
	    }
	}
	
	public void setHeight(int iHeight) {
		this.height = iHeight;
	}
	
	public int getWidth() {
		if(width==0 && root!=null)
			return computeWidth(root,getHeight());
		return width;
	}
	
	private int computeWidth(MerkleNode node, int level) {
		int lheight=0, rheight=0;
		if (node == null)
	        return 0;
	    else
	    {
	        if(node.getLeftChild()!=0)
	        	lheight = computeWidth(getNodeById(node.getLeftChild()), level-1);
	        if(node.getRightChild()!=0)
	        	rheight = computeWidth(getNodeById(node.getRightChild()), level-1);
	 
	        /* use the larger one */
	        if (level == 1)
	            return 1;
	    }
		return lheight+ rheight;
	}

	public void setWidth(int width) {
		this.width = width;
	}
	
	private MerkleNode getEmptyNode(NodeType type) {
		return new MerkleNode(s.hashSHA256(new byte[32]),0,0,0,0,type);
	}
	
	public int Size(){
		return tNodes.size();
	}

	public HashMap<Integer, MerkleNode> gettNodes() {
		return tNodes;
	}

	public void settNodes(HashMap<Integer, MerkleNode> tNodes) {
		this.tNodes = tNodes;
	}
	
	
}
