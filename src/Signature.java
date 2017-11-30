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

  public static void main(String[] args) {
    if(args.length < 1) {
      throw new RuntimeException("file path required");
    }

    BigInteger p = new BigInteger(PRIMEMOD, 16);
    BigInteger g = new BigInteger(GENERATOR, 16);
    BigInteger x = RandGen.inRange(BigInteger.ONE, p.subtract(BigInteger.ONE));

    BigInteger pubKey = modpow(g, x, p);

    System.out.println("PUBLIC KEY:\n" + pubKey.toString(16));

    BigInteger m = readFile(args[0]);
    BigInteger h = hash(m);

    BigInteger r;
    BigInteger s;
    do {
      BigInteger k;
      BigInteger tmpGcd;
      do {
        k = RandGen.inRange(BigInteger.ZERO, p.subtract(BigInteger.ONE));
        
        //TODO: remove this printing
        tmpGcd = gcd(k, p.subtract(BigInteger.ONE));
        System.out.println(tmpGcd.toString());
      } while ( tmpGcd.compareTo(BigInteger.ONE) != 0 );

      r = modpow(g, k, p);
      s = modinv(h.subtract(x.multiply(r)), k).mod(p.subtract(BigInteger.ONE));

    } while (s.compareTo(BigInteger.ZERO) == 0);


    // FINAL CHECKS
    if (r.max(BigInteger.ZERO).compareTo(r.min(p)) != 0) {
      throw new RuntimeException("not 0 < r < p");
    }
    if (s.max(BigInteger.ZERO).compareTo(s.min(p.subtract(BigInteger.ONE))) != 0) {
      throw new RuntimeException("not 0 < s < p-1");
    }

    // TODO: Perform signature check (maybe)
    // BigInteger v1 = modpow(pubKey, r , new BigInteger);
    // BigInteger v2 = modpow(r, s, r.add(BigInteger.ONE));
    // if(modpow(g, h, p).compareTo((v1.multiply(v2)).mod(p)) != 0 ) {
    //   throw new RuntimeException("not a valid signature");
    // }

    System.out.println("R:\n" + r.toString(16));
    System.out.println("S:\n" + s.toString(16));
  }

  // TODO: Own implementation
  static BigInteger modpow(BigInteger n, BigInteger e, BigInteger m) {
    return n.modPow(e, m);
  }

  // TODO: Own implementation
  static BigInteger gcd(BigInteger a, BigInteger b) {
    return a.gcd(b);
  }

  // TODO: Own implementation
  static BigInteger modinv(BigInteger i, BigInteger m) {
    return i.modInverse(m);
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
