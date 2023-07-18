 
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class client
{
  private static BigInteger publicKey;
  private static BigInteger clientID ;
  public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException, NoSuchAlgorithmException,NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException 
  {  
    functions func = new functions();
    Socket s = new Socket("localHost", 5253);
      //  Setting up Input and Output Streams
    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

        //Sending Setup Request
    System.out.println("\n" + "Sent to Server:");
    String request = "Setup_Request: Hello" ;
    oos.writeObject(request);
    System.out.println("1. " + request);
    System.out.println("Client ----------------------> Server" + "\n");

    //Recieving Server's RSA public key
       publicKey = new BigInteger(String.valueOf(ois.readObject()));
    BigInteger n = new BigInteger(String.valueOf(ois.readObject()));
   // System.out.println("Server is calculating RSA public key... " + "\n");
    System.out.println("Server sent: ");
//---
    String rsapk = "RSA Public Key: " + publicKey.toString() + " and RSA value n (large prime numbers p and g multipied together)";
    System.out.println("2. " + rsapk);
    System.out.println("Client <---------------------- Server" + "\n");


    //Creating Client ID from user Input
    BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
    PrintWriter out = new PrintWriter(s.getOutputStream(), true);
    System.out.println("Enter your 9 digit ClientID: "); 
    Scanner stdIn = new Scanner(System.in);
    while(!stdIn.hasNextInt()) 
    {
      System.out.println("\n" + "NOTE: CLIENTID MUST INCLUDE ONLY NUMBERS AND LESS THAN 9 DIGITS! " + "\n" + "\n" + "Please enter again:"); 
      stdIn = new Scanner(System.in);
    }
    clientID = new BigInteger(stdIn.nextLine());
    stdIn.close();
     
     

     // Sending clientID to server
    System.out.println("Sent to Server:");
    String idc = "clientID (IDc): " + clientID;
    System.out.println("3. " + idc);
    System.out.println("Client ----------------------> Server" + "\n");
    oos.writeObject(clientID.toString());

    //Recieving ServerID and SessionID
    System.out.println("Server sent: ");
    BigInteger ServerID = new BigInteger(String.valueOf(ois.readObject()));
    BigInteger sessionID = new BigInteger(String.valueOf(ois.readObject()));
    System.out.println("4. ServerID: " + ServerID + " , SessionID: " + sessionID);
    System.out.println("Client <---------------------- Server" + "\n");

        
    //Recieving and verifing RSA signature
    System.out.println("Server has created and sent their RSA Digitial Signature" + "\n");
    BigInteger sig = new BigInteger(String.valueOf(ois.readObject()));
    if (functions.verifyDigitalSignature(sig, publicKey, n, ServerID)) {
      System.out.println("\n" + "Server verified! Connection is secure! :)" + "\n");
    } else {
      System.out.println("\n" + "Client: Connection compromised. Risk of MITM attack! Exiting...");
    };

    //generate DHprivate key
    BigInteger DHpriv = functions.calcDHPrivKey();

    //generate DH public key
    BigInteger DHpub = functions.calcDHpublicKey(DHpriv);

    //Sending DH public key
    System.out.println("Sent to Server: ");
    oos.writeObject(DHpub);
    System.out.println("5. Client Diffie Helman public key. ");
    System.out.println("Client ----------------------> Server" + "\n");

    //Reiceving Server DH public key
    System.out.println("Server Sent ");
    BigInteger serverDHpub = new BigInteger(String.valueOf(ois.readObject()));
    System.out.println("6. Server Diffie Helman public key. ");
    System.out.println("Client <---------------------- Server" + "\n");
      BigInteger DHsig = new BigInteger(String.valueOf(ois.readObject()));
    if (functions.verifyDigitalSignature(DHsig, publicKey, n, ServerID)) {
      System.out.println("\n" + "Server's Diffie Helman is secure." + "\n");
    } else {
      System.out.println("\n" + "Client: Server's Diffie Helman is compromised. Risk of MITM attack! Exiting...");
    };

    //Calculating DH shared key
    BigInteger DHsharedkey = functions.calcDHsharedKey(serverDHpub, DHpriv, sessionID);

    //Key confirmation




    String shareddhstr = String.valueOf(DHsharedkey);
    BigInteger clientDHverify = functions.sha256(shareddhstr);
    oos.writeObject(clientDHverify);
    BigInteger serververify = new BigInteger(String.valueOf(ois.readObject()));
    if(serververify.equals(clientDHverify))
    {
      System.out.println("Shared keys confirmed to be indentical" + "\n");
    }else{
      System.out.println("Shared keys are not indentical" + "\n");
    };





    //Encrypted message 1
    System.out.println("Client: Receiving encrypted message...");
    String sessionIDstr = String.valueOf(sessionID);
    BigInteger sessionIDhashed = functions.sha256(sessionIDstr);
    String encrypted = (String.valueOf(ois.readObject()));
    System.out.println("\n" + "Recieved encrypted form: " + encrypted);
    String decrypted = functions.Decrypt(encrypted, sessionIDhashed);
    System.out.println("\n" + "Decrypted message: " + decrypted);


    //verifing Hash Mac
    String hmac = (String.valueOf(ois.readObject()));
    if(hmac.equals(functions.HMAC(sessionIDstr, decrypted).toString())){
      System.out.println("\n" + "Hashed based Message Authentication codes verified." + "\n" + "Authentic data exchange successfull.");
    }else{
      System.out.println("Hashed based Message Authentication codes  not verified." + "\n" + "Authentic data exchange failed.");
    }

//-------------------------------------------------------------------------------------------------------------------------------

    System.out.println("\n" + "Initiating Authentication for second message transmission..." + "\n");


 //Recieving Server's RSA public key
        publicKey = new BigInteger(String.valueOf(ois.readObject()));
    n = new BigInteger(String.valueOf(ois.readObject()));
    System.out.println("Server sent: ");

    rsapk = "RSA Public Key: " + publicKey.toString() + " and RSA value n (large prime numbers p and g multipied together)";
    System.out.println("7. " + rsapk);
    System.out.println("Client <---------------------- Server" + "\n");




     
     

  

        
    //Recieving and verifing RSA signature
    System.out.println("Server has created and sent their RSA Digitial Signature" + "\n");
    sig = new BigInteger(String.valueOf(ois.readObject()));
    if (functions.verifyDigitalSignature(sig, publicKey, n, ServerID)) {
      System.out.println("\n" + "Server verified! Connection is secure! :)" + "\n");
    } else {
      System.out.println("\n" + "Client: Connection compromised. Risk of MITM attack! Exiting...");
    };

    //generate DHprivate key
    DHpriv = functions.calcDHPrivKey();

    //generate DH public key
    DHpub = functions.calcDHpublicKey(DHpriv);

    //Sending DH public key
    System.out.println("Sent to Server: ");
    oos.writeObject(DHpub);
    System.out.println("8. Client Diffie Helman public key. ");
    System.out.println("Client ----------------------> Server" + "\n");

    //Reiceving Server DH public key
    System.out.println("Server Sent ");
    serverDHpub = new BigInteger(String.valueOf(ois.readObject()));
    System.out.println("9. Server Diffie Helman public key. ");
    System.out.println("Client <---------------------- Server" + "\n");
    DHsig = new BigInteger(String.valueOf(ois.readObject()));
    if (functions.verifyDigitalSignature(DHsig, publicKey, n, ServerID)) {
      System.out.println("\n" + "Server's Diffie Helman is secure." + "\n");
    } else {
      System.out.println("\n" + "Client: Server's Diffie Helman is compromised. Risk of MITM attack! Exiting...");
    };

    //Calculating DH shared key
   DHsharedkey = functions.calcDHsharedKey(serverDHpub, DHpriv, sessionID);

    //Key confirmation




    shareddhstr = String.valueOf(DHsharedkey);
    clientDHverify = functions.sha256(shareddhstr);
    oos.writeObject(clientDHverify);
    serververify = new BigInteger(String.valueOf(ois.readObject()));
    if(serververify.equals(clientDHverify))
    {
      System.out.println("Shared keys confirmed to be indentical" + "\n");
    }else{
      System.out.println("Shared keys are not indentical" + "\n");
    };


//-------------------------------------------------------------------------------------------------------------------------------



    //Encrypt Message 2
    System.out.println("\n" + "Client: Receiving encrypted message...");
    String encrypted2 = (String.valueOf(ois.readObject()));
    System.out.println("\n" + "Recieved encrypted form: " + encrypted2);
    String decrypted2 = functions.Decrypt(encrypted2, sessionIDhashed);
    System.out.println("\n" + "Decrypted message: " + decrypted2);


    //verifing Hash Mac
    String hmac2 = (String.valueOf(ois.readObject()));
    if(hmac2.equals(functions.HMAC(sessionIDstr, decrypted2).toString())){
      System.out.println("\n" + "Hashed based Message Authentication codes verified." + "\n" + "Authentic data exchange successfull.");
    }else{
      System.out.println("Hashed based Message Authentication codes  not verified." + "\n" + "Authentic data exchange failed." + "\n");
    }

    System.out.println("\n" + "-------------------------------------------------------------" + "\n");

  }
            
}
      
    
