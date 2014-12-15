import thep.paillier.EncryptedInteger;
import thep.paillier.PrivateKey;
import thep.paillier.PublicKey;
import util.TransformMgt;

import java.awt.*;
import java.io.*;
import java.math.BigInteger;

public class Main
{
    private static final BigInteger threshold = new BigInteger("1000000");

    public static void main(String[] args)
    {
        PrivateKey privkey = new PrivateKey(128);
        PublicKey pubkey = privkey.getPublicKey();

        String privateKeyString = null;
        String publicKeyString = null;
        try {
            System.out.println("----------------Private Key------------------");
            privateKeyString = TransformMgt.toString(privkey);
            publicKeyString = TransformMgt.toString(pubkey);
            System.out.println(privateKeyString);
            System.out.println("----------------Public Key-------------------");
            System.out.println(publicKeyString);
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            pubkey = (PublicKey) TransformMgt.fromString(publicKeyString);
            String aString = "100";
            String bString = "-200";

            System.out.println();
            System.out.println("a = " + aString);
            System.out.println("b = " + bString);
            EncryptedInteger a = new EncryptedInteger(new BigInteger(aString), pubkey);
            System.out.println("Enc_pub(a) = " + a.getCipherVal());

            EncryptedInteger b = new EncryptedInteger(new BigInteger(bString), pubkey);
            System.out.println("Enc_pub(b) = " + b.getCipherVal());

            EncryptedInteger c = a.add(b);
            System.out.println("c = Enc_pub(a) + Enc_pub(a) = " + c.getCipherVal());

            PrivateKey pri = (PrivateKey) TransformMgt.fromString(privateKeyString);

            BigInteger decryptedC = c.decrypt(pri);

            if (decryptedC.compareTo(threshold) == 1)
                decryptedC = decryptedC.subtract(pubkey.getN());

            System.out.println("Dec_priv(c) = " + decryptedC);
        } catch (Exception ex) {
            ex.getStackTrace();
        }
    }
}
