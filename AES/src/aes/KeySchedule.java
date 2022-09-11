/*
 * AES KeySchedule Implementation 
 * by Abir Ahmed (100765777)
 */
package aes;

public class KeySchedule {
	
	//round constant
	static final byte rcon[][] = {{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1B, 0x36}, //that (byte) is needed because java byte types are signed and therefore limited to 128
								  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
								  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
								  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	
	private byte[][] _currentKey;
	private int numOfKeyGenerated;
	
	
	//RotWord Step
	public static byte[][] rotateColumn(final byte[][] block, int columnIndex) {
		byte [][] rotColumn = AES.cloneArray(block);
		
		for (int i=0; i< AES.ARRAYSIZE-1; i++) {
			rotColumn[i][columnIndex] = block[i+1][columnIndex];
		}
		rotColumn[AES.ARRAYSIZE - 1][columnIndex] = block[0][columnIndex];

		
		return rotColumn;
	}
	
	public KeySchedule(byte[][] key) {
		
		_currentKey = key;
		numOfKeyGenerated = 0;
		
	}
	
	private byte[] computeInitialColumn(byte[][] substituted) {
		byte[] initialColumn = new byte[4];
		for (int i=0; i < AES.ARRAYSIZE; i++) {
			initialColumn[i] = (byte) (_currentKey[i][0] ^ substituted[i][AES.ARRAYSIZE-1]  ^ rcon[i][numOfKeyGenerated]);
			//System.out.println("Current " + String.format("%02x",_currentKey[i][0]) + " Substituted "+ String.format("%02x",substituted[i][AES.ARRAYSIZE-1]) + " rcon " + rcon[i][numOfKeyGenerated]);
		}
		
		return initialColumn;
	}
	
	private byte[][] rconXorStep(byte[][] substitutedKey) {
		
		byte[][] tempKeyBlock = new byte[AES.ARRAYSIZE][AES.ARRAYSIZE];
		byte[] tempColumn;
		tempColumn = computeInitialColumn(substitutedKey);
		
		for (int i=0; i < AES.ARRAYSIZE; i++) {
			tempKeyBlock[i][0] = tempColumn[i];
		}
		//first column is now populated for the key block
		
		//Start at the second column
		for (int i=0; i < AES.ARRAYSIZE; i++) {
			for (int j=1; j < AES.ARRAYSIZE; j++) {
				//XOR with previous column we generated in previous loop
				tempKeyBlock[i][j] = (byte) (tempKeyBlock[i][j-1] ^ _currentKey[i][j]);
			}
		}
		
		return tempKeyBlock;
	}
	
	public byte[][] generateNextKeyBlock() {
		byte[][] rotated;
		byte[][] substituted;
		
		//Uncomment lines below to see each step of the KeyScheduler
//		System.out.println("Pre Rotated Column KeySchedule");
//		System.out.println(AES.blockToString(_currentKey));
		
		//rotate last column
		rotated = KeySchedule.rotateColumn(_currentKey, AES.ARRAYSIZE - 1);
		
//		System.out.println("Post Rotated Column KeySchedule");
//		System.out.println(AES.blockToString(rotated));
		
		//While its only needed to be done on the last column, just do the whole thing to reuse code
		substituted = AES.subBytes(rotated);
		
//		System.out.println("Substituted Block KeySchedule");
//		System.out.println(AES.blockToString(substituted));
		
		_currentKey = rconXorStep(substituted);
		
		System.out.println("New Key Block KeySchedule");
		System.out.println(AES.blockToString(_currentKey));
		
		numOfKeyGenerated++;
		return _currentKey;
	}
}
