package demo.jcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;

/** Project-owned Java Card applet; executed by jCardSim, not a carrier eSIM.
 *  Its APDU surface has no key import, private-key export or key-regeneration command.
 *  The simulator and its JVM remain software; this is not physical key protection.
 */
public final class DeviceSignerApplet extends Applet {
    private final KeyPair pair;
    private final Signature signer;
    private boolean locked;
    private boolean signing;

    private DeviceSignerApplet() {
        pair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        // NIST P-256 / secp256r1 parameters. Set both keys before on-card keygen.
        configure((ECKey) pair.getPublic());
        configure((ECKey) pair.getPrivate());
        pair.genKeyPair();
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        register();
    }

    public static void install(byte[] data, short offset, byte length) {
        new DeviceSignerApplet();
    }

    private static void configure(ECKey key) {
        key.setFieldFP(P, (short) 0, (short) P.length);
        key.setA(A, (short) 0, (short) A.length);
        key.setB(B, (short) 0, (short) B.length);
        key.setG(G, (short) 0, (short) G.length);
        key.setR(R, (short) 0, (short) R.length);
        key.setK((short) 1);
    }

    @Override public void deselect() { signing = false; }

    @Override public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x80) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        byte instruction = buffer[ISO7816.OFFSET_INS];
        if (buffer[ISO7816.OFFSET_P2] != 0 || (instruction != (byte) 0x30 && buffer[ISO7816.OFFSET_P1] != 0)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (instruction == (byte) 0x10) {
            short size = ((ECPublicKey) pair.getPublic()).getW(buffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, size);
            return;
        }
        if (instruction == (byte) 0x30) {
            byte value = buffer[ISO7816.OFFSET_P1];
            if (value != 0 && value != 1) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            locked = value == 1;
            signing = false;
            return;
        }
        if (instruction == (byte) 0x40) {
            buffer[0] = 1; // applet protocol version
            buffer[1] = 1; // P-256 + SHA-256
            buffer[2] = (byte) (locked ? 1 : 0);
            buffer[3] = (byte) (pair.getPrivate().isInitialized() ? 1 : 0);
            apdu.setOutgoingAndSend((short) 0, (short) 4);
            return;
        }
        if (instruction != (byte) 0x20 && instruction != (byte) 0x21 && instruction != (byte) 0x22) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        if (locked) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (instruction == (byte) 0x20) {
            signer.init(pair.getPrivate(), Signature.MODE_SIGN);
            signing = true;
            return;
        }
        if (!signing) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short received = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        if (length > 220 || received != length) {
            signing = false;
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short offset = apdu.getOffsetCdata();
        if (instruction == (byte) 0x21) {
            signer.update(buffer, offset, length);
        } else {
            signing = false;
            short size = signer.sign(buffer, offset, length, buffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, size);
        }
    }

    // Public curve parameters; none of these constants is secret key material.
    private static final byte[] P = bytes(new short[]{255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255});
    private static final byte[] A = bytes(new short[]{255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,255,255,252});
    private static final byte[] B = bytes(new short[]{90,198,53,216,170,58,147,231,179,235,189,85,118,152,134,188,101,29,6,176,204,83,176,246,59,206,60,62,39,210,96,75});
    private static final byte[] G = bytes(new short[]{4,107,23,209,242,225,44,66,71,248,188,230,229,99,164,64,242,119,3,125,129,45,235,51,160,244,161,57,69,216,152,194,150,79,227,66,226,254,26,127,155,142,231,235,74,124,15,158,22,43,206,51,87,107,49,94,206,203,182,64,104,55,191,81,245});
    private static final byte[] R = bytes(new short[]{255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,81});
    private static byte[] bytes(short[] values) {
        byte[] result = new byte[values.length];
        for (short i = 0; i < values.length; i++) result[i] = (byte) values[i];
        return result;
    }
}
