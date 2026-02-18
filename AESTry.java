import java.util.Arrays;
import java.nio.charset.StandardCharsets;

public class AESChallenge {

    public static byte[] hexToBytes(String hex) {
        String s = hex.replaceAll("\\s+", "");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static byte[] decryptCBC(byte[] key, byte[] ciphertext) throws Exception {
        Object rk = Rijndael_Algorithm.makeKey(Rijndael_Algorithm.DECRYPT_MODE, key);

        int blocks = (ciphertext.length / 16) - 1;
        byte[] pt = new byte[blocks * 16];

        byte[] prev = Arrays.copyOfRange(ciphertext, 0, 16);

        for (int i = 0; i < blocks; i++) {
            int offset = (i + 1) * 16;
            byte[] ci = Arrays.copyOfRange(ciphertext, offset, offset + 16);

            byte[] decrypted = Rijndael_Algorithm.blockDecrypt2(ci, 0, rk);

            for (int j = 0; j < 16; j++)
                pt[i * 16 + j] = (byte) (decrypted[j] ^ prev[j]);

            prev = ci;
        }

        return pt;
    }

    public static boolean looksAscii(byte[] data) {
        for (byte b : data) {
            int v = b & 0xFF;
            if (v < 32 || v > 127) return false;
        }
        return true;
    }

    public static void main(String[] args) throws Exception {

        String cipherHex =
            "354C0FCABE7852DF42BC9DD6EAAB495C" +
            "CB8B6158C93E2D5D2A49387717657ECE" +
            "B6CAD9A517BD123AE58C720DF9CDFEA3" +
            "B4132FBAE66DF6001A032BF627FC406B" +
            "3F71931E4F818265157028D2212DAD85";

        byte[] ciphertext = hexToBytes(cipherHex);

        // Build constant rightmost 95 bits
        byte[] baseKey = new byte[16];

        // Set the known 95-bit pattern:
        // 1100 .... 000011

        // Rightmost nibble = 0011
        baseKey[15] = 0x03;

        // 87 zero bits automatically satisfied (array initialized to 0)

        // Set nibble 1100 at correct location
        // 95 bits from right means 128-95 = 33 bits from left
        // So the 1100 starts at bit position 33

        // That lands in byte index 4
        baseKey[4] |= 0xC0;   // 1100xxxx

        long max = 1L << 33;

        for (long candidate = 0; candidate < max; candidate++) {

            byte[] key = Arrays.copyOf(baseKey, 16);

            // Insert 33 brute force bits
            for (int i = 0; i < 4; i++)
                key[i] = (byte)((candidate >> (8*(3-i))) & 0xFF);

            key[4] |= (byte)((candidate & 1) << 5);

            byte[] pt = decryptCBC(key, ciphertext);

            if (looksAscii(pt)) {
                System.out.println("KEY FOUND!");
                System.out.println("Plaintext: " + new String(pt, StandardCharsets.US_ASCII));
                break;
            }
        }
    }
}