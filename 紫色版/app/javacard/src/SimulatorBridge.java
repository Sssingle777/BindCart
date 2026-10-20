package demo.jcard;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/** Host-side APDU transport only. This class never gets a KeyPair or PrivateKey.
 *  stdin:  <decimal-request-id> TAB <hex-APDU> LF
 *  stdout: READY TAB <pid> TAB <hex-public-point> LF
 *          <request-id> TAB OK TAB <hex-response-including-SW> LF
 *  Any simulator diagnostic goes to stderr, never into the protocol stream.
 */
public final class SimulatorBridge {
    private static final byte[] AID_BYTES = fromHex("F00000000144494401");
    public static void main(String[] args) throws Exception {
        PrintStream protocol = System.out;
        System.setOut(System.err);
        // Fail closed if the deterministic upstream RNG class is accidentally
        // loaded instead of our audited local SecureRandom replacement.
        Class<?> entropy = Class.forName("com.licel.jcardsim.crypto.SecureRandomNullProvider");
        if (!entropy.getProtectionDomain().getCodeSource().getLocation().equals(
                SimulatorBridge.class.getProtectionDomain().getCodeSource().getLocation())) {
            throw new IllegalStateException("SECURE_RANDOM_PATCH_NOT_LOADED");
        }
        System.clearProperty("com.licel.jcardsim.randomdata.seed");
        System.setProperty("com.licel.jcardsim.randomdata.secure", "1");
        Simulator simulator = new Simulator();
        AID aid = new AID(AID_BYTES, (short) 0, (byte) AID_BYTES.length);
        simulator.installApplet(aid, DeviceSignerApplet.class);
        if (!simulator.selectApplet(aid)) throw new IllegalStateException("APPLET_SELECT_FAILED");
        byte[] point = simulator.transmitCommand(fromHex("8010000000"));
        if (point.length != 67 || point[65] != (byte) 0x90 || point[66] != 0) throw new IllegalStateException("PUBLIC_KEY_FAILED");
        protocol.println("READY\t" + ProcessHandle.current().pid() + "\t" + toHex(point, point.length - 2));
        protocol.flush();
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        String line;
        while ((line = input.readLine()) != null) {
            String[] fields = line.split("\t", -1);
            if (fields.length != 2 || !fields[0].matches("[1-9][0-9]{0,12}") || fields[1].length() > 520) {
                protocol.println("0\tERR\tINVALID_FRAME"); protocol.flush(); continue;
            }
            try {
                byte[] command = fromHex(fields[1]);
                if (command.length < 4 || command.length > 260) throw new IllegalArgumentException();
                byte[] response = simulator.transmitCommand(command);
                protocol.println(fields[0] + "\tOK\t" + toHex(response, response.length));
            } catch (Throwable error) {
                protocol.println(fields[0] + "\tERR\tAPDU_FAILED");
            }
            protocol.flush();
        }
    }
    private static byte[] fromHex(String text) {
        if (text.length() % 2 != 0 || !text.matches("[0-9a-fA-F]+")) throw new IllegalArgumentException();
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    private static String toHex(byte[] value, int length) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] out = new char[length * 2];
        for (int i = 0; i < length; i++) { int b = value[i] & 255; out[i * 2] = digits[b >>> 4]; out[i * 2 + 1] = digits[b & 15]; }
        return new String(out);
    }
}
