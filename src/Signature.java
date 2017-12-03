import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

class RandGen {
  static byte[] generate() {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[128];
    random.nextBytes(bytes);
    return bytes;
  }

  static BigInteger inRange(BigInteger min, BigInteger max) {
    BigInteger n;
    SecureRandom sr = new SecureRandom();
    do {
      n = new BigInteger(max.bitLength(), sr);
    } while (n.compareTo(min) > 0 && n.compareTo(max) < 0);
    return n;
  }
}

public class Signature {
  static final String PRIMEMOD = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
  static final String GENERATOR = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";

  static final BigInteger i0 = BigInteger.ZERO;
  static final BigInteger i1 = BigInteger.ONE;

  public static void main(String[] args) {
    if(args.length < 1) {
      throw new RuntimeException("file path required");
    }

    BigInteger p = new BigInteger(PRIMEMOD, 16);
    BigInteger g = new BigInteger(GENERATOR, 16);
    BigInteger h = hash(readFile(args[0]));

    // Helpers
    BigInteger pm1 = p.subtract(i1);

    BigInteger x = RandGen.inRange(i0, pm1);

    BigInteger y = modpow(g, x, p);

    BigInteger r = BigInteger.ZERO;
    BigInteger s = BigInteger.ZERO;
    while (s.equals(i0)) {
      BigInteger k;
      do {
        k = RandGen.inRange(i0, pm1);
      } while(!gcd(k, pm1).equals(i1));

      r = modpow(g, k, p);

      BigInteger xr = x.multiply(r);

      s = h.subtract(xr).multiply(modinv(k, pm1)).mod(pm1);
    }

    // FINAL CHECKS
    if (!r.max(i0).equals(r.min(p))) {
      throw new RuntimeException("not 0 < r < p");
    }
    if (!s.max(i0).equals(s.min(pm1))) {
      throw new RuntimeException("not 0 < s < p-1");
    }

    BigInteger v1 = modpow(y, r, p);
    BigInteger v2 = modpow(r, s, p);

    BigInteger left = modpow(g, h, p);
    BigInteger right = (v1.multiply(v2)).mod(p);

    if(!left.equals(right)) {
      throw new RuntimeException("not a valid signature");
    }

    System.out.println("PUBLIC KEY:\n" + y.toString(16));
    System.out.println("\nR:\n" + r.toString(16));
    System.out.println("\nS:\n" + s.toString(16));
  }

  static BigInteger modpow(BigInteger n, BigInteger e, BigInteger m) {
    return n.modPow(e, m);
  }

  static BigInteger gcd(BigInteger a, BigInteger b) {
    return xgcd(a,b)[0];
  }

  static BigInteger modinv(BigInteger i, BigInteger m) {
    return xgcd(i, m)[1].mod(m);
  }

  static BigInteger[] xgcd(BigInteger a, BigInteger b) {
  	BigInteger[] qr = new BigInteger[2];

  	BigInteger x = BigInteger.ONE, lastX = BigInteger.ZERO;
  	BigInteger y = BigInteger.ZERO, lastY = BigInteger.ONE;

    BigInteger r = BigInteger.ZERO, xr = BigInteger.ZERO;
  	while (true){
  	    qr = a.divideAndRemainder(b); r = qr[0]; a = qr[1];
  	    x = x.subtract(y.multiply(r));
  	    lastX = lastX.subtract(lastY.multiply(r));
  	    if (a.equals(BigInteger.ZERO)) {
          r = b; xr = y; break;
        };
  	    qr = b.divideAndRemainder(a); r = qr[0]; b = qr[1];
  	    y = y.subtract(x.multiply(r));
  	    lastY = lastY.subtract(lastX.multiply(r));
  	    if (b.equals(BigInteger.ZERO)) {
          r = a; xr = x; break;
        };
  	}

    BigInteger[] res = {r, xr};
    return res;
  }

  static BigInteger hash(BigInteger m) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return new BigInteger(digest.digest(m.toByteArray()));
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  static BigInteger readFile(String file) {
    try {
      File f = new File(file);
      FileInputStream fs = new FileInputStream(f);
      byte[] data = new byte[(int)f.length()];
      fs.read(data);
      fs.close();
      return new BigInteger(data);
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }
}
