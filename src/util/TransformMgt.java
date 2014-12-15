package util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.*;

/**
 * Created by ben on 14/12/15.
 */
public class TransformMgt
{
    static BASE64Decoder base64Decoder = new BASE64Decoder();
    static BASE64Encoder base64Encoder = new BASE64Encoder();

    /**
     * Read the object from Base64 string.
     */
    public static Object fromString(String s) throws IOException, ClassNotFoundException
    {
        byte[] data = base64Decoder.decodeBuffer(s);
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Write the object to a Base64 string.
     */
    public static String toString(Serializable o) throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return new String(base64Encoder.encode(baos.toByteArray()));
    }
}
