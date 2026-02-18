import java.util.Arrays;

public class AESChallenge{
    public static byte[] hexToBytes(String hex) {
        String s = hex.replaceAll("\\s+", ""); // Gets rid of all spaces
        if (s.length() % 2 != 0) throw new IllegalArgumentException("Hex must have even length.");

        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid hex at index " + (2 * i));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String bytesToHex(byte[] data) {
        char[] hex = "0123456789ABCDEF".toCharArray(); // Like a lookup table
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(hex[(b >>> 4) & 0x0F]);
            sb.append(hex[b & 0x0F]);
        }
         return sb.toString();
    }

    public static byte[] AESCbcDecrypt(byte[] key16, byte[] ciphertextWithIv) {
        if (key16 == null || key16.length != 16) throw new IllegalArgumentException("Key must be 16 bytes.");
        if (ciphertextWithIv == null || ciphertextWithIv.length < 32 || ciphertextWithIv.length % 16 != 0)
            throw new IllegalArgumentException("Ciphertext must be multiple of 16 and include IV.");

        Object rk = Rijndael_Algorithm.makeKey(Rijndael_Algorithm.DECRYPT_MODE, key16);
        int blocks = (ciphertextWithIv.length / 16) - 1; // exclude IV
        byte[] pt = new byte[blocks * 16];
        byte[] prev = Arrays.copyOfRange(ciphertextWithIv, 0, 16);

        for (int i = 0; i < blocks; i++) {
            int off = (i + 1) * 16;
            byte[] ci = Arrays.copyOfRange(ciphertextWithIv, off, off + 16);
            byte[] di = Rijndael_Algorithm.blockDecrypt2(ci, 0, rk);
            for (int j = 0; j < 16; j++) pt[i * 16 + j] = (byte) (di[j] ^ prev[j]);
            prev = ci;
        }
        return pt;
    }
    public static boolean looksLikeAscii(byte[] pt) {
        for (byte b : pt) {
            int v = b & 0xff;
            if (v < 32 || v > 126) return false;  // printable ASCII
        }
        return true;
    }

    public static void main(String[] args) {
        String challengeHex =
                "354C0FCABE7852DF42BC9DD6EAAB495C" +
                "CB8B6158C93E2D5D2A49387717657ECE" +
                "B6CAD9A517BD123AE58C720DF9CDFEA3" +
                "B4132FBAE66DF6001A032BF627FC406B" +
                "3F71931E4F818265157028D2212DAD85";

        byte[] msg = hexToBytes(challengeHex);
        byte[] iv = Arrays.copyOfRange(msg, 0, 16);
        int blocks = (msg.length / 16) - 1;

        System.out.println("IV: " + bytesToHex(iv));
        System.out.println("Cipher blocks (excluding IV): " + blocks);

        for (int last = 0; last <= 0xFF; last++) {
            byte[] candidateKey = new byte[16];
            candidateKey[15] = (byte) last;

            byte[] pt = AESCbcDecrypt(candidateKey, msg);

            if (looksLikeAscii(pt)) {                 // your validity check
                System.out.println("KEY = " + bytesToHex(candidateKey));
                System.out.println(new String(pt, StandardCharsets.US_ASCII));
                break;                                // stop once found
            }
        }

    }
}