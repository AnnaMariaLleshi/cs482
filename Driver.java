public class Driver {
    //Our ciphertext
    public static byte[] cipherText = { (byte) 0x35, (byte) 0x4C, (byte) 0x0F, (byte) 0xCA, 
    (byte) 0xBE, (byte) 0x78, (byte) 0x52, (byte) 0xDF, (byte) 0x42, (byte) 0xBC, (byte) 0x9D,
    (byte) 0xD6, (byte) 0xEA, (byte) 0xAB, (byte) 0x49, (byte) 0x5C, (byte) 0xCB, (byte) 0x8B,
    (byte) 0x61, (byte) 0x58, (byte) 0xC9, (byte) 0x3E, (byte) 0x2D, (byte) 0x5D, (byte) 0x2A,
    (byte) 0x49, (byte) 0x38, (byte) 0x77, (byte) 0x17, (byte) 0x65, (byte) 0x7E, (byte) 0xCE,
    (byte) 0xB6, (byte) 0xCA, (byte) 0xD9, (byte) 0xA5, (byte) 0x17, (byte) 0xBD, (byte) 0x12,
    (byte) 0x3A, (byte) 0xE5, (byte) 0x8C, (byte) 0x72, (byte) 0x0D, (byte) 0xF9, (byte) 0xCD,
    (byte) 0xFE, (byte) 0xA3, (byte) 0xB4, (byte) 0x13, (byte) 0x2F, (byte) 0xBA, (byte) 0xE6,
    (byte) 0x6D, (byte) 0xF6, (byte) 0x00, (byte) 0x1A, (byte) 0x03, (byte) 0x2B, (byte) 0xF6,
    (byte) 0x27, (byte) 0xFC, (byte) 0x40, (byte) 0x6B, (byte) 0x3F, (byte) 0x71, (byte) 0x93,
    (byte) 0x1E, (byte) 0x4F, (byte) 0x81, (byte) 0x82, (byte) 0x65, (byte) 0x15, (byte) 0x70,
    (byte) 0x28, (byte) 0xD2, (byte) 0x21, (byte) 0x2D, (byte) 0xAD, (byte) 0x85}; 

    public static byte[] inkey = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
                                  (byte) 0x60, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
                                  (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
                                  (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03};

    public static PrintWriter out;

    public static void bruteDecrypt(byte[] bruteinkey) throws Exception {
        Object decryptRoundKeys = Rijndael_Algorithm.makeKey(Rijndael_Algorithm.DECRYPT_MODE, bruteinkey);
        int numberofCipherBlocks = cipherText.length / 16 - 1;
        byte[] cleartextBlocks = new byte[numberofCipherBlocks * 16];
        byte[] recievedIV = new byte[16];

        for (int i = 0; i < 16; i++){
            recievedIV[i] = cipherText[i];
        }

        byte[] currentDecryptionBlock = new byte[16];

        for (int i = 0; i < numberofCipherBlocks; i ++){
            for(int j = 0; j < 16; j++) {
                currentDecryptionBlock[j] = cipherText[(i + 1) * 16 + j];
            }

            byte[] decryptedBlock = Rijndael_Algorithm.blockDecrypt2(currentDecryptionBlock, 0, decryptRoundKeys);

            for (int j = 0; j < 16; j++){
                cleartextBlocks[i * 16 + j] = (byte) (decryptedBlock[j] ^ cipherText[i * 16 + j]);
            }
        }

        String recoveredString = new String (cleartextBlocks);

        if (recoveredString.matches("\\A\\p(ASCII)+\\z")){
            System.out.println("KEY FOUND!");
            System.out.println("\tRecovered String: " + recoveredString);
            System.out.println("\tIV: " + toString(recievedIV));
            System.out.println("\tinKey: " + toString(bruteinkey) + "\n\n");
        } 
    }

    public static String convertToString (byte[] data) {
		char[] _hexArray = {'0', '1', '2', '3', '4', '5','6', '7', '8',
			    '9', 'A', 'B', 'C', 'D', 'E', 'F'};

		StringBuffer sb = new StringBuffer();

		for (int i=0; i <data.length; i++) {
			sb.append("" + _hexArray[(data[i] >> 4) & 0x0f] + _hexArray[data[i] & 0x0f]);
		}

		return sb.toString();
	}

    public static void main(String[] args) throws Exception {
        int computer_num = Integer.parseInt(args [0]);
        try {
            out = new Printwriter ("output-" + computer_num + "txt");
        }catch (Exception ex) {
            Systen.err println("File Not Found");
            return;
        }
        long startTime = System.nanoTime ();

        for (int i - 255; 1 >= 0; i--) {
            inKey[0] = (byte) i;
            
            for(int j = 255; j >= 0; j--) {
                inKey[1] = (byte) j;

                for(int k = 255; k >= 0; k--){
                    inKey[2] = (byte) k;

                    for (int l = 255; i >= 0; l--){
                    inKey[3] = (byte) 1;
                    inKey[4] = (byte) 0x60;
                    bruteDecrypt (inKey);
                    inKey[4] = (byte) OxE0;
                    bruteDecrypt (inkey) ;
                    }
                }
            }
        }

        long endTime = System.nanoTime();
        out.println("Time Taken: " + (endTime - startTime) / 1000000000 + "seconds");
        out.close();
    }
}