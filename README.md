# AES_java-python


JAVA와 PYTHON에서 동일하게 동작하는 AES 암호화/복호화 샘플

### Python 소스

~~~
from Crypto.Cipher import AES
import base64
import hashlib

BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

if __name__ == '__main__':
    key = '12345678901234567890123456789012' # 32bit
    iv = '1234567890123456' # 16bit
    
    beforeCipher = 'abcd'
    print 'Input string: ' + beforeCipher

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    beforeCipher = pad(beforeCipher)
    afterCipher = base64.b64encode(cipher.encrypt(beforeCipher))
    print 'Cipher string: ' + afterCipher

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    deciphed = cipher.decrypt(base64.b64decode(afterCipher))
    deciphed = unpad(deciphed)
    print 'Deciphed string: [' + deciphed +']'
~~~

### JAVA 소스

~~~
package lahuman;

import org.junit.Assert;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import static org.hamcrest.Matchers.is;


public class Test {

    @org.junit.Test
    public void test() throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String key = "12345678901234567890123456789012";
        String iv = "1234567890123456";

        String beforeCipher = "abcd";
        System.out.println("Input string: " + beforeCipher);

        SecretKey keyspec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        AlgorithmParameterSpec ivspec = new IvParameterSpec(iv.getBytes("UTF-8"));

        //Encription
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
        int blockSize = cipher.getBlockSize();
        byte[] dataBytes = beforeCipher.getBytes("UTF-8");

         //find fillChar & pad
        int plaintextLength = dataBytes.length;
        int fillChar = ((blockSize - (plaintextLength % blockSize)));
        plaintextLength += fillChar;
        byte[] plaintext = new byte[plaintextLength];
        Arrays.fill(plaintext, (byte) fillChar);
        System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

        byte[] cipherBytes = cipher.doFinal(plaintext);
        String afterCiphered = new String(Base64.getEncoder().encodeToString(cipherBytes));
        System.out.println("Cipher string: " + afterCiphered);

        //Decription
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
        byte[] base64decoded = Base64.getDecoder().decode(afterCiphered.getBytes("UTF-8"));
        byte[] aesdecode = cipher.doFinal(base64decoded);
        
        // unpad
        byte[] origin = new byte[aesdecode.length - (aesdecode[aesdecode.length - 1])];
        System.arraycopy(aesdecode, 0, origin, 0, origin.length);

        String originStr =  new String(origin, "UTF-8");
        System.out.println("Decipher string: [" + originStr + "]");
    }
}    
~~~

> Java에서 Python의 pad, unpad와 똑같이 동작 하기 위하여 Encryption시 fillChar을 찾고 pad처리를 하고, Decryption시 unpad 처리를 한다.

## 참고 자료

[Python Java AES ](http://bcllemon.github.io/2015/10/29/2015/python-java-aes/)
