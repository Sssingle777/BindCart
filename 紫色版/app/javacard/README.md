# jCardSim device backend

This project uses an actual jCardSim Java Card runtime to execute the custom
`demo.jcard.DeviceSignerApplet`. It does not emulate a mobile carrier eSIM,
eUICC provisioning or physical secure-element protection.

Run from the new `a2a-jcardsim-x402` project:

```sh
node scripts/setup-jcardsim.mjs
node scripts/jcardsim-selftest.mjs
node --test test/jcardsim.test.mjs test/esim.test.mjs
```

The self-test prints `JCARD_APDU_ES256_VERIFIED` only after a real APDU signature
has been verified through the public DID key. It also checks that the unsupported
private-key export command returns `6d00` and that a locked applet refuses to sign.
Normal application startup builds the Java classes if their source hash changes.

`setup-jcardsim.mjs` downloads only checksum-pinned dependencies into this project.
The bundled JDK download is Eclipse Temurin 21.0.12.1+1 for macOS Apple Silicon;
set `JCARD_JAVA_HOME` to a JDK 11+ on other platforms. No system Java installation,
shell profile, global package or global `JAVA_HOME` is changed. JDK provenance is
also recorded in `.runtime/jdk-source.json`; its legal notices are in the bundled
JDK `legal` directory. Existing files with a wrong checksum are rejected.

## Source and dependency provenance

* Java Card simulator upstream: <https://github.com/licel/jcardsim>, Apache-2.0.
* Downloaded binary distribution: **`com.klinec:jcardsim:3.0.6.0`**, published on
  Maven Central from <https://github.com/ph4r05/jcardsim>. This is a community fork
  distribution, not a claim that this Maven package is Licel's latest release.
* Exact URLs, SHA-256 values and checked Maven SHA-1 values for the simulator and
  ASM 7.2 dependencies: `../vendor/jcardsim/manifest.json`. The simulator JAR is
  `db6de7ffde71651c45d00df7e160771685cec3e14e444bf36b796658d289942f` (SHA-256).
* jCardSim is Apache-2.0; ASM is BSD-3-Clause. The distribution also shades Bouncy
  Castle 1.71, Kryo 5.2.0 and transitive classes; their component licenses and
  notices remain applicable. The original POM and notices are retained in vendor.
* `DeviceSignerApplet.java`, `SimulatorBridge.java`, the Node APDU bridge and its
  tests were written for this project. No vendor eSIM SDK or proprietary applet
  was imported.

## Mandatory simulator RNG patch

The downloaded fork's `SecureRandomNullProvider` uses an unseeded digest PRNG.
An initial real runtime test found that fresh JVMs generated the same P-256 key.
Using that default would defeat the device-key security model.

`src/SecureRandomNullProvider.java` is a small, explicitly local replacement that
uses JDK `java.security.SecureRandom`, obtaining entropy inside the JVM. Its class
is placed before the unchanged vendor JAR on the JVM classpath. The bridge checks
the loaded class's code source at startup and refuses to run if the patch is not
loaded. It also enables the fork's secure `RandomData` option. No seed is passed
from Node, and no private scalar is imported or exported. Tests require distinct
public keys across JVM sessions and distinct ECDSA signatures across repeated
operations. This is a simulator infrastructure patch, not a portable Java Card
applet feature.

## APDU contract and execution boundaries

AID: `F00000000144494401`. Proprietary CLA: `80`.

| INS | Operation | Data / response |
| --- | --- | --- |
| `10` | Export public key | 65-byte uncompressed P-256 point |
| `20` | Start ECDSA/SHA-256 signing | No data |
| `21` | Feed signing input | At most 220 bytes |
| `22` | Finish signing | Last chunk; DER ECDSA response |
| `30` | Lock/unlock | `P1=01` / `00` |
| `40` | Public applet status | Version, curve, lock, initialized flag |

The applet generates its P-256 key via Java Card `KeyPair.genKeyPair()` during
installation. The Java host uses only `Simulator.transmitCommand()`; the Node host
holds only the public JWK and signatures. DER signatures are converted to JOSE's
64-byte P1363 format and verified before sending a device proof. Unsupported
instructions, including the private-export probe `11`, return `6d00`.

The HTTP device service still verifies caller permission, A's signature, the VC,
B's signed challenge and exact request binding. It reserves a challenge before
awaiting the APDU operation. A failed or unknown APDU outcome leaves that challenge
consumed. Sign transactions are serialized so streamed chunks cannot interleave.
The runtime must remain available; there is no Node signing fallback.

The access-token and request-policy checks live in the Node service, while the
key operation and lock live in the applet. Someone controlling the device Node
process or JVM can still use or inspect this software simulator. Each restart
creates a fresh card/key; there is no carrier profile, hardware extraction test,
CAP conversion, real-card installation, persistent key store or remote attestation.
