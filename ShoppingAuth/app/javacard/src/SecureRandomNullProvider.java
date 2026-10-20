package com.licel.jcardsim.crypto;

import java.security.SecureRandom;

/** Project-local runtime compatibility/security patch for com.klinec 3.0.6.0.
 *  The published simulator's class of this name uses an unseeded deterministic
 *  digest PRNG, causing fresh JVMs to generate identical key pairs. The bridge
 *  classpath deliberately places this replacement before the original JAR.
 *  JDK SecureRandom obtains system entropy inside the JVM; Node never supplies
 *  seeds or keys. This changes simulator infrastructure, not the card applet.
 */
final class SecureRandomNullProvider extends SecureRandom {
    public SecureRandomNullProvider() { super(); }
}
