 
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.net.Socket;
import java.security.*;
import java.util.Random;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.math.*;
import java.lang.Math;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class functions{
      private static BigInteger p ;
       private static BigInteger g ;
       private static BigInteger RSAp ;
       private static BigInteger RSAq ;
       private static BigInteger e;
       private static BigInteger hashed1;
        private static String IVector = "encryptionIntege";
      //private BigInteger n;
        public functions(){
        p = new BigInteger("178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
        g = new BigInteger("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");
    //n = new BigInteger("30986213306077240753081052253961359620671067024090837587614076776525479516902871168855022791280057976269042823595017310200670817551711901310467831028808560821812754436530975836165013085595149826742428988252129275540491187552514523588057198386461645199589123193783258220040842311124981928623274699805171165721399848288135996311416508896743643886284311498245090728513504064610360422259927030987730164449292453910213688060421350831001723007487938592792937753361380374140380906172602001012275962677946330838164077361961834887387928012880061741134552920123283524288417284677363577242246166466958908041067050516711923714470")
    }




//𝕯𝖎𝖋𝖋𝖎𝖊 𝕳𝖊𝖑𝖒𝖆𝖓 𝕰𝖕𝖍𝖊𝖒𝖊𝖗𝖆𝖑


    public static BigInteger calcDHPrivKey(){
        System.out.println("Calculating Diffie-Helman Private key..." + "\n"); 
        BigInteger DHpriv = getPrime();
        while(DHpriv.compareTo(DHpriv) == 1){
            DHpriv = getPrime();
        }
        System.out.println("Diffie-Helman Private key created."+ "\n"); 
        return DHpriv;
    }

    public static BigInteger calcDHpublicKey(BigInteger DHpriv){
        System.out.println("Calculating Diffie-Helman Public key..." + "\n"); 
         // System.out.println("p = " + p);
        //   System.out.println( "g =  " + g ); 
         //   System.out.println("DHpriv.  " + DHpriv ); 
        BigInteger DHpublic = fastModularExp(g , DHpriv, p);
        System.out.println("Diffie-Helman Public key created."+ "\n");
        return DHpublic;
    }


    //Creating Shared Diffie Helman ephemeral key
    public static BigInteger calcDHsharedKey(BigInteger DHpub, BigInteger DHpri, BigInteger sessionID){
        System.out.println("Calculating shared key..." + "\n" );
        BigInteger DHshared = (fastModularExp(DHpub, DHpri, p));//.subtract(sessionID);
           System.out.println("Diffie-Helman Ephemeral shared key created."+ "\n"); 
        return DHshared;
    }





  //      public void setN(BigInteger n)
  //  {
  //      this.n = n;
  //  }

    public static BigInteger getN(){

        //functions.p = BigInteger p;
        //functions.g = BigInteger g;
        RSAp = getPrime();
        RSAq = getPrime();
        BigInteger n = RSAp.multiply(RSAq);
        return n;

    }

    public static BigInteger getD(BigInteger publickey){

        BigInteger phiN;
        phiN = RSAp.subtract(BigInteger.ONE).multiply(RSAq.subtract(BigInteger.ONE));
        BigInteger e = publickey;
        BigInteger d =  e.modInverse(phiN);
        return d;
    }

    //𝕱𝖆𝖘𝖙 𝕸𝖔𝖉𝖚𝖑𝖆𝖗 𝕰𝖝𝖕𝖔𝖓𝖊𝖓𝖙𝖎𝖆𝖙𝖎𝖔𝖓

         public static BigInteger fastModularExp(BigInteger b , BigInteger e, BigInteger n) 
    //Where b = base, e = exponent, n = modulus
    {
        if(n.equals(BigInteger.ONE)){
            return new BigInteger("0");
        }
        BigInteger rs = new BigInteger("1");

        while(e.compareTo(BigInteger.ZERO) == 1)
        {
            if((e.and(BigInteger.ONE)).equals(BigInteger.ONE)){
                rs = rs.multiply(b).mod(n);
            }
           e = e.shiftRight(1);
            b = (b.multiply(b)).mod(n);
        }
        return rs;
    }

        //𝕾𝕳𝕬-256 𝕳𝖆𝖘𝖍 𝕱𝖚𝖓𝖈𝖙𝖎𝖔𝖓

        public static BigInteger sha256(String input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;

    }

        public static BigInteger getPrime(){
        Random rand = new SecureRandom();
        return BigInteger.probablePrime(2048, rand);
    }




        //using equation:
        //signature = H(message)^d mod n
        //where message is hashed using SHA256, d is the private key and n is p and q multiplied together
        public static BigInteger DigitalSignature(BigInteger message, BigInteger publickey)
    {
        BigInteger digitalsignature;
          BigInteger e = publickey;
        //    System.out.println(e.toString() ); 
       // String hashedstr = sha256(message);
        String message1 = String.valueOf(message) ;
        BigInteger hashed1 = sha256(message1).abs();
      //    System.out.println("sig hash:    " + hashed1);
        BigInteger d = getD(e);
    
        BigInteger n = RSAp.multiply(RSAq);

      // System.out.println("n" + n);
        digitalsignature = fastModularExp(hashed1, d, n);
        return digitalsignature;
    }

    // h(m) = s^e mod n
     public static boolean verifyDigitalSignature(BigInteger digitalsignature, BigInteger publickey, BigInteger n, BigInteger serverID)
    {
   
            BigInteger e = publickey;
            String message2 = String.valueOf(serverID);

            BigInteger hash = sha256(message2).abs();

          
            BigInteger hashedmessage = fastModularExp(digitalsignature, e, n);

            if(hash.equals(hashedmessage))
            {
                System.out.println("Digital Signature Verified!");
                return true;
            }
            else
            {
                System.out.println("Digital Signature Doesn't Match");
               return false;
            }
           // return;
          
    }


//𝕳𝕸𝕬𝕮 𝕱𝖚𝖓𝖈𝖙𝖎𝖔𝖓

      public static String HMAC(String key, String message) throws NoSuchAlgorithmException, IOException {

        // Hashing session key
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] keyHash;
        BigInteger bikeyhash = sha256(key);
        keyHash = bikeyhash.toByteArray();
        byte[] messageBytes = message.getBytes();

        // Creating Ipad/Opad
        byte[] opad = new byte[32];
        byte[] ipad = new byte[32];

        for(int i = 0; i < keyHash.length; i++) {

            opad[i] = (byte)(keyHash[i] ^ 0x5c);
            ipad[i] = (byte)(keyHash[i] ^ 0x36);

        }

        // Hash opad and ipad byte arrays
        byte[] keyOpadHash = d.digest(opad);
        byte[] keyIpadHash = d.digest(ipad);

        // Concat all byte arrays then hash the final array
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(keyOpadHash);
        os.write(keyIpadHash);
        os.write(messageBytes);

        byte[] HMACfinal = d.digest(os.toByteArray());

        //Convert byte array to hex string
        StringBuilder sb = new StringBuilder();
        for(byte b : HMACfinal){
            sb.append(String.format("%02x",b));
        }

        return sb.toString();
    }

        //AES CBC encryption
    public static String Encrypt(String message, BigInteger sessionKey) {

        try {
           // String messageWithHmac; //= new String;
            IvParameterSpec iv = new IvParameterSpec(IVector.getBytes("UTF-8"));
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec sessionkeySpec = new SecretKeySpec(sessionKey.toByteArray(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, sessionkeySpec, iv);
           String encrypted = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8"))); // encrypts
           
            // String sessionkeystr = String.valueOf(sessionKey);                                                                                                   // message
                  return encrypted;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }


        //AES CBC Decryption
       public static String Decrypt(String encrypted, BigInteger sessionKey) {
        try {
            IvParameterSpec iv = new IvParameterSpec(IVector.getBytes("UTF-8"));
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec sessionkeySpec = new SecretKeySpec(sessionKey.toByteArray(), "AES");
            
            cipher.init(Cipher.DECRYPT_MODE, sessionkeySpec, iv);
//String encryptedstr = new String(Base64.getEncoder().encode( encrypted.getBytes(StandardCharsets.UTF_8)));
            return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }



   }