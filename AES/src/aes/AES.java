/*
 * AES Implementation 
 * @author Abir Ahmed (100765777)
 */
package aes;

import java.lang.Math;
import java.util.Stack;
public class AES {

	static final int BLOCKSIZE = 16;
	static final int ARRAYSIZE = (int) Math.sqrt(AES.BLOCKSIZE);
	
	static final int[][] sBox = {
			{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
	
	static final int[][] invBox = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

	private byte[][] _keyBlock;
	
	/*
	 * Clones an N x N array. .clone() function will not work because Java just clones the reference pointers and not a deep clone for 2D array
	 */
	public static byte[][] cloneArray(byte[][] old){
		byte[][] newInstance = new byte[AES.ARRAYSIZE][AES.ARRAYSIZE];
		for(int i=0; i<old.length; i++) {
			for(int j=0; j<old[i].length; j++) {
				newInstance[i][j]=old[i][j];
			}
		}
		return newInstance;
	}
	
	//Converts a string of space separated hex string to a N x N byte array block
	public static byte[][] convertToBlock(String str) {
		int arraysize = (int) Math.sqrt(BLOCKSIZE);
		byte block[][] = new byte[arraysize][arraysize];
		
		//Split string into an array based on spaces to a maximum of blocksize
		String[] arrOfText = str.split(" ", AES.BLOCKSIZE);
		
		//Convert single dimensional array into a 4x4 array
		for (int i=0; i < AES.BLOCKSIZE; i++) {
			block[i%arraysize][i/arraysize] = (byte) Integer.parseUnsignedInt(arrOfText[i], 16);
		}
		
		return block;
	}
	
	//Converts a N x N byte block to a string in grid format
	public static String blockToString(final byte[][] block) {
		int dimensionLength = (int) Math.sqrt(AES.BLOCKSIZE);
		StringBuffer sb = new StringBuffer();
		
		for (int i=0; i<dimensionLength; i++) {
			for (int j=0; j<dimensionLength; j++) {
				sb.append(String.format("%02x",block[i][j]).toUpperCase());
				sb.append("\t");
			}
			sb.append("\n");
		}
		return sb.toString();
	}
	
	//Uses the sBox to substitute elements in the N x N block based on high/low nibbles
	public static byte[][] subBytes(byte[][] block) {
		int arraysize = (int) Math.sqrt(BLOCKSIZE);
		byte[][] subBlock = new byte[arraysize][arraysize];
		
		for (int i=0;i<arraysize; i++) {
			for (int j=0;j<arraysize;j++) {
				//Use first 4 bits to look up row, last 4 bits to look up column in the sBox
				subBlock[i][j] = (byte) AES.sBox[(block[i][j] & 0xF0) >> 4][block[i][j] & 0x0F]; 
			}
		}
		
		return subBlock;
	}
	
	//Uses the inverted sBox to substitute elements in the N x N block based on high/low nibbles
	public static byte[][] invSubBytes(byte[][] block) {
		int arraysize = (int) Math.sqrt(BLOCKSIZE);
		byte[][] subBlock = new byte[arraysize][arraysize];
		
		for (int i=0;i<arraysize; i++) {
			for (int j=0;j<arraysize;j++) {
				//Use first 4 bits to look up row, last 4 bits to look up column in the sBox
				subBlock[i][j] = (byte) AES.invBox[(block[i][j] & 0xF0) >> 4][block[i][j] & 0x0F]; 
			}
		}
		
		return subBlock;
	}
	
	/**
	 * @param byteArray an array of bytes to shift
	 * @return a byte array shifted right
	 */
	public static byte[] shiftByteArrayRight(byte[] byteArray) {
		byte shiftedArray[] = new byte[byteArray.length];
		
		for (int i=1; i<byteArray.length; i++) {
			shiftedArray[i] = byteArray[i-1];
		}
		shiftedArray[0] = byteArray[byteArray.length - 1];
		return shiftedArray;
	}
	
	/**
	 * @param byteArray an array of bytes to shift
	 * @return a byte array shifted left
	 */
	public static byte[] shiftByteArrayLeft(byte[] byteArray) {
		byte shiftedArray[] = new byte[byteArray.length];
		
		for (int i=0; i<byteArray.length-1; i++) {
			shiftedArray[i] = byteArray[i+1];
		}
		
		shiftedArray[byteArray.length-1] = byteArray[0];
		return shiftedArray;
	}
	
	/**
	 * @param a Converts a byte array to a Hex string
	 * @return returns a space separated hex string from a byte array
	 */
	public static String byteArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for(byte b: a) {
			sb.append(String.format("%02x", b).toUpperCase());
			sb.append(" ");
		}
		return sb.toString();
	}
	
	//Multiply by 2 in the Galois Field is done with a left shift and a conditional XOR with X"1B" if the MSB is 1
	//https://en.wikipedia.org/wiki/Rijndael_MixColumns
	private static byte GMul(byte a, int b) { // Galois Field (256) Multiplication of two Bytes
	    byte p = 0;

	    for (int counter = 0; counter < 8; counter++) {
	        if ((b & 1) != 0) {
	            p ^= a;
	        }
	        
	        boolean hi_bit_set = (a & 0x80) != 0;
	        a <<= 1;
	        if (hi_bit_set) {
	            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1  = 0b11011*/
	        }
	        b >>= 1;
	    }

	    return p;
	}
	

	/**
	 * This constructor takes a space separated string key in hex
	 * @param key String that contains 16 hex values separated by a space
	 */
	public AES(String key) {
		this(AES.convertToBlock(key));
	}
	
	
	/**
	 * @param key 4x4 byte array of your AES key that will be used for encryption and decryption
	 */
	public AES(byte[][] key) {
		_keyBlock = key;

		System.out.println("key Block");
		System.out.println(AES.blockToString(_keyBlock));
	}


	/**
	 * @param plaintextString is a space separated string of hex values 16 bytes long
	 * @return 4 x 4 byte matrix decrypted data
	 */
	public byte[][] encrypt(String plaintextString){
		return encrypt(AES.convertToBlock(plaintextString));
	}
	/**
	 * @param plaintextBlock 
	 * @return 4 x 4 byte array of the final cyphertext
	 */
	public byte[][] encrypt(byte[][] plaintextBlock){
		byte[][] roundedBlock;
		byte[][] substitutedBlock;
		byte[][] shiftedBlock;
		byte[][] mixedBlock;
		byte[][] computedKeyBlock;
		
		
		KeySchedule ks = new KeySchedule(_keyBlock);
		
		System.out.println("Plain Text Block");
		System.out.print(AES.blockToString(plaintextBlock));
		
		//initial AddRoundKey Step
		roundedBlock = _addRoundKey(plaintextBlock, _keyBlock);
		System.out.println("Initial Rounded");
		System.out.println(AES.blockToString(roundedBlock));
		
		//Do this 9 times. For 192bit key do 11 and 256 do 13
		for (int i = 0; i < 9; i++) {
			System.out.println("-".repeat(35)); //Print hiphens to demark the beginning of next round
			System.out.println(" Encrypt Round " + (i+1));
			
			//SubBytes step
			substitutedBlock = _subBytes(roundedBlock);
			System.out.println("Substituted");
			System.out.println(AES.blockToString(substitutedBlock));
			
			//ShiftRows step
			shiftedBlock = _shiftRows(substitutedBlock);
			System.out.println("Shifted");
			System.out.println(AES.blockToString(shiftedBlock));
			
			//MixColumns Step
			mixedBlock = _mixColumns(shiftedBlock);
			System.out.println("Mixed");
			System.out.println(AES.blockToString(mixedBlock));
			
			//AddRoundKey
			computedKeyBlock = ks.generateNextKeyBlock();
			roundedBlock = _addRoundKey(mixedBlock, computedKeyBlock);
			System.out.println("Rounded");
			System.out.println(AES.blockToString(roundedBlock));
		}
		
		System.out.println("-".repeat(35));
		
		//final SubBytes step
		substitutedBlock = _subBytes(roundedBlock);
		System.out.println("Last Substituted");
		System.out.println(AES.blockToString(substitutedBlock));
		
		//Final ShiftRows step
		shiftedBlock = _shiftRows(substitutedBlock);
		System.out.println("Shifted");
		System.out.println(AES.blockToString(shiftedBlock));
		
		//AddRoundKey
		computedKeyBlock = ks.generateNextKeyBlock();
		roundedBlock = _addRoundKey(shiftedBlock, computedKeyBlock);
		System.out.println("Final Ciphertext output");
		System.out.println(AES.blockToString(roundedBlock));
		
		
		return roundedBlock;
	}
	
	/**
	 * @param encryptedString is a space separated string of hex values 16 bytes long
	 * @return 4 x 4 byte matrix decrypted data
	 */
	public byte[][] decrypt(String encryptedString){
		return decrypt(AES.convertToBlock(encryptedString));
	}
	
	/**
	 * @param encryptedBlock that is encrypted with the key specified in the constructor of AES
	 * @return 4 x 4 byte matrix decrypted data
	 */
	public byte[][] decrypt(byte[][] encryptedBlock){
		//Work in progress
		byte[][] roundedBlock;
		byte[][] substitutedBlock;
		byte[][] shiftedBlock;
		byte[][] mixedBlock;
		byte[][] roundKeyScheduleBlock;
		Stack<byte[][]> roundKeys = new Stack<byte[][]>(); //using this just for decrypt since we need to know the last round, need to calculate all previous rounds
		KeySchedule ks = new KeySchedule(_keyBlock);

		System.out.println("Encrypted Text Block");
		System.out.println(AES.blockToString(encryptedBlock));
		
		System.out.println("-".repeat(35));
		System.out.println("Generating all round key blocks for decryption");
		for (int i=0; i<10; i++) { //generate all 10 roundkeys for 128 bit
			roundKeys.push(ks.generateNextKeyBlock());
		}
		System.out.println("-".repeat(35));
		
		roundKeyScheduleBlock = roundKeys.pop();
		System.out.println("RoundKey");
		System.out.println(AES.blockToString(roundKeyScheduleBlock));
		
		roundedBlock = _addRoundKey(encryptedBlock, roundKeyScheduleBlock);
		System.out.println("Initial Rounded");
		System.out.println(AES.blockToString(roundedBlock));
		
		shiftedBlock = _invShiftRows(roundedBlock);
		System.out.println("Inverse Shifted");
		System.out.println(AES.blockToString(shiftedBlock));
		
		
		//first invSubBytes step
		substitutedBlock = _invSubBytes(shiftedBlock);
		System.out.println("Inverse Substituted");
		System.out.println(AES.blockToString(substitutedBlock));
		
		for (int i=0; i<9; i++) {
			System.out.println("-".repeat(35)); //Print hyphens to demark the beginning of next round
			System.out.println(" Decrypt Round " + (i+1));
			
			
			roundKeyScheduleBlock = roundKeys.pop();
			System.out.println("RoundKey");
			System.out.println(AES.blockToString(roundKeyScheduleBlock));
			
			//AddRoundKey 
			roundedBlock = _addRoundKey(substitutedBlock, roundKeyScheduleBlock);
			System.out.println("Rounded");
			System.out.println(AES.blockToString(roundedBlock));
			
			//InvMixColumns Step
			mixedBlock = _invMixColumns(roundedBlock);
			System.out.println("Inverse Mixed");
			System.out.println(AES.blockToString(mixedBlock));
			
			//InvShiftColumns Step
			shiftedBlock = _invShiftRows(mixedBlock);
			System.out.println("Inverse Shifted");
			System.out.println(AES.blockToString(shiftedBlock));
			
			//InvSubBytes Step
			substitutedBlock = _invSubBytes(shiftedBlock);
			System.out.println("Inverse Substituted");
			System.out.println(AES.blockToString(substitutedBlock));
			
		}
		
		System.out.println("-".repeat(35));
		
		//final roundkey step, use the key 
		roundedBlock = _addRoundKey(substitutedBlock, _keyBlock);
		System.out.println("Final Decrypted output");
		System.out.println(AES.blockToString(roundedBlock));
		
		return null;
	}
	
	/**
	 * @param block 4 x 4 byte matrix to do inverted shift rows for decryption step
	 * @return 4 x 4 byte matrix with shifted rows
	 */
	private byte[][] _invShiftRows(byte[][] block){
		byte[][] shiftedBlock = AES.cloneArray(block);
		
		for (int i=0; i<AES.ARRAYSIZE; i++) {
			//System.out.println("Shifting row " + i + " " + i + " times");
			for (int j=0; j<i; j++) {
				//System.out.println(byteArrayToHex(shiftByteArrayLeft(shiftedBlock[i])));
				shiftedBlock[i] = AES.shiftByteArrayRight(shiftedBlock[i]);
			}
		}
		return shiftedBlock;
	}
	
	
	/**
	 * @param block is a 4x4 byte matrix where inverted substitution step for decryption on
	 * @return a 4x4 byte matrix where all the elements have gone through the invSBox substitution
	 */
	private byte[][] _invSubBytes(byte[][] block){
		return AES.invSubBytes(block);
	}
	
	//http://www.herongyang.com/Cryptography/AES-MixColumns-Procedure-Algorithm.html
	/*
	 *    |a1|   |0x0E 0x0B 0x0D 0x09|   |b1|
   		  |a2|   |0x09 0x0E 0x0B 0x0D|   |b2|
   	      |a3| = |0x0D 0x09 0x0E 0x0B| ● |b3|
      	  |a4|   |0x0B 0x0D 0x09 0x0E|   |b4|
	 */
	private byte[][] _invMixColumns(byte[][] block){
		byte a1,a2,a3,a4;
		final int arraysize = (int) Math.sqrt(AES.BLOCKSIZE);
		byte mixedBlock[][] = new byte[arraysize][arraysize];
		
		
		//The following can be optimized but keeping it this way for being readable and simple
		for (int i=0; i<arraysize; i++) {
			//Purposely keeping lines verbose to align with the comments of the function _mixColumns for clarification
			a1 = (byte) (GMul((byte) 0x0E, block[0][i]) ^ GMul((byte) 0x0B, block[1][i]) ^ GMul((byte) 0x0D, block[2][i]) ^ GMul((byte) 0x09, block[3][i]));
			a2 = (byte) (GMul((byte) 0x09, block[0][i]) ^ GMul((byte) 0x0E, block[1][i]) ^ GMul((byte) 0x0B, block[2][i]) ^ GMul((byte) 0x0D, block[3][i]));
			a3 = (byte) (GMul((byte) 0x0D, block[0][i]) ^ GMul((byte) 0x09, block[1][i]) ^ GMul((byte) 0x0E, block[2][i]) ^ GMul((byte) 0x0B, block[3][i]));
			a4 = (byte) (GMul((byte) 0x0B, block[0][i]) ^ GMul((byte) 0x0D, block[1][i]) ^ GMul((byte) 0x09, block[2][i]) ^ GMul((byte) 0x0E, block[3][i]));
			
			mixedBlock[0][i] = a1;
			mixedBlock[1][i] = a2;
			mixedBlock[2][i] = a3;
			mixedBlock[3][i] = a4;
		}
		
		return mixedBlock;
		
	}
	
	
	//This can be a static method since it doesn't use any instance variables but keeping it normal
	//to match every stage as part of the Rijndael Cipher flash animation
	private byte[][] _addRoundKey(byte[][] inputBlock, byte[][] keyBlock){
		final int arraysize = (int) Math.sqrt(AES.BLOCKSIZE);
		byte[][] roundedBlock = new byte[arraysize][arraysize];
		
		for (int i=0; i<arraysize; i++) {
			for (int j=0; j<arraysize; j++) {
				roundedBlock[i][j] = (byte) (inputBlock[i][j] ^ keyBlock[i][j]);
			}
		}
		return roundedBlock;
	}
	
	private byte[][] _subBytes(byte[][] block){
		return AES.subBytes(block);
	}
	
	private byte[][] _shiftRows(byte[][] block){
		final int arraysize = (int) Math.sqrt(AES.BLOCKSIZE);
		byte[][] shiftedBlock = AES.cloneArray(block);
		
		for (int i=0; i<arraysize; i++) {
			//System.out.println("Shifting row " + i + " " + i + " times");
			for (int j=0; j<i; j++) {
				//System.out.println(byteArrayToHex(shiftByteArrayLeft(shiftedBlock[i])));
				shiftedBlock[i] = AES.shiftByteArrayLeft(shiftedBlock[i]);
			}
		}
		return shiftedBlock;
	}
	
	//http://www.herongyang.com/Cryptography/AES-MixColumns-Procedure-Algorithm.html
	/*
	 *    |a1|   |0x02 0x03 0x01 0x01|   |b1|
   		  |a2|   |0x01 0x02 0x03 0x01|   |b2|
   	      |a3| = |0x01 0x01 0x02 0x03| ● |b3|
      	  |a4|   |0x03 0x01 0x01 0x02|   |b4|
	 */
	private byte[][] _mixColumns(byte[][] block){
		byte a1,a2,a3,a4;
		final int arraysize = (int) Math.sqrt(AES.BLOCKSIZE);
		byte mixedBlock[][] = new byte[arraysize][arraysize];
		
		/*
		 * The commented block below was a sample based on the Rijndael Cipher flash animation for testing and verify the same output
		 * https://www.youtube.com/watch?v=gP4PqVGudtg
		int[][] block1 = {{0xd4, 0xe0, 0xb8, 0x1e},
					  	  {0xbf, 0xb4, 0x41, 0x27},
					  	  {0x5d, 0x52, 0x11, 0x98},
					  	  {0x30, 0xae, 0xf1, 0xe5}};
		*/
		
		//The following can be optimized but keeping it this way for being readable and simple
		for (int i=0; i<arraysize; i++) {
			//Purposely keeping lines verbose to align with the comments of the function _mixColumns for clarification
			a1 = (byte) (GMul((byte) 0x02, block[0][i]) ^ GMul((byte) 0x03, block[1][i]) ^ GMul((byte) 0x01, block[2][i]) ^ GMul((byte) 0x01, block[3][i]));
			a2 = (byte) (GMul((byte) 0x01, block[0][i]) ^ GMul((byte) 0x02, block[1][i]) ^ GMul((byte) 0x03, block[2][i]) ^ GMul((byte) 0x01, block[3][i]));
			a3 = (byte) (GMul((byte) 0x01, block[0][i]) ^ GMul((byte) 0x01, block[1][i]) ^ GMul((byte) 0x02, block[2][i]) ^ GMul((byte) 0x03, block[3][i]));
			a4 = (byte) (GMul((byte) 0x03, block[0][i]) ^ GMul((byte) 0x01, block[1][i]) ^ GMul((byte) 0x01, block[2][i]) ^ GMul((byte) 0x02, block[3][i]));
			
			mixedBlock[0][i] = a1;
			mixedBlock[1][i] = a2;
			mixedBlock[2][i] = a3;
			mixedBlock[3][i] = a4;
		}
		
		return mixedBlock;
		
	}
	
	public static void main(String[] args) {
		byte [][] cipherText, decryptedText;
		
		//AES aes = new AES("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01");
		//cipherText = aes.encrypt("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
		
		//This is the sample used to test based on https://www.youtube.com/watch?v=gP4PqVGudtg
		//AES aes = new AES("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C");
		//cipherText = aes.encrypt("32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34");
		
		AES aes = new AES("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C");
		cipherText = aes.encrypt("6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A");
		decryptedText = aes.decrypt(cipherText);
		
	}

}
