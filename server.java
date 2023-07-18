 
import java.net.Socket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

//Se
public class server
{
	  private static ServerSocket ss = null;
	  private static BigInteger publicKey = new BigInteger("65537");
	  private static BigInteger serverID = new BigInteger("4357895457467853");
	  private static BigInteger sessionID = new BigInteger("00000000001");
	  private static BigInteger n = new BigInteger("8977982345");
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException
    {
			
		functions func = new functions();
	    ss = new ServerSocket(5253);
	    Socket s = ss.accept();
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());

	    //Recieving Setup_request
	    System.out.println("Client sent: " ); 
	    System.out.println("1. " + ois.readObject());
	    System.out.println("Client ----------------------> Server" + "\n");

	    //Sending RSA public key
	    System.out.println("Sent to Client: ");
	    String rsapk = "RSA_PK: " + publicKey.toString();
	    System.out.println("2. " + rsapk + " and RSA value n (large prime numbers p and g multipied together)");
	    oos.writeObject(publicKey.toString());
	    BigInteger n = functions.getN();
	    oos.writeObject(n);
	    System.out.println("Client <---------------------- Server" + "\n");

	    //Recieving Client ID
	    System.out.println("Client sent:");
	    BigInteger clientID = new BigInteger(String.valueOf(ois.readObject()));
	 	System.out.println("3. clientID (IDc): " + clientID);
		System.out.println("Client ----------------------> Server" + "\n");

		//sending server ID and session ID
		System.out.println("Sent to Client: ");
	    oos.writeObject(serverID);
	    oos.writeObject(sessionID);
	    System.out.println("4. ServerID: " + serverID + " , SessionID: " + sessionID);
	    System.out.println("Client <---------------------- Server" + "\n");

	     

	 	//generate and store RSA private key
	    BigInteger d = functions.getD(publicKey);
	    System.out.println("RSA Private Key has been generated.");

	    //Generate and send RSA signature
	    BigInteger sig;
		sig = functions.DigitalSignature(serverID, publicKey);
		System.out.println("Digitial Signature created" + "\n");		
		oos.writeObject(sig);

		//generate DHprivate key
		BigInteger DHpriv = functions.calcDHPrivKey();

		//generate DH public key
		BigInteger DHpub = functions.calcDHpublicKey(DHpriv);


		//Sending DH public key
		System.out.println("Sent to Client: ");
	    oos.writeObject(DHpub);
	    oos.writeObject(sig);
	    System.out.println("5. Server Diffie Helman public key. ");
	    System.out.println("Client ----------------------> Server" + "\n");

	    //Reiceving Client DH public key
	    System.out.println("Client sent: ");
	    BigInteger clientDHpub = new BigInteger(String.valueOf(ois.readObject()));
	    System.out.println("6. Client Diffie Helman public key. ");
	    System.out.println("Client ----------------------> Server" + "\n");



	    //Calculating DH shared key
	    BigInteger DHsharedkey = functions.calcDHsharedKey(clientDHpub, DHpriv, sessionID);

	          //Key confirmation
	    String shareddhstr = String.valueOf(DHsharedkey);
	    BigInteger serverDHverify = functions.sha256(shareddhstr);
	    oos.writeObject(serverDHverify);
	    BigInteger clientverify = new BigInteger(String.valueOf(ois.readObject()));
	    if(clientverify.equals(serverDHverify))
	    {
	      	System.out.println("Shared keys confirmed to be indentical" + "\n");
	    }else{
	      	System.out.println("Shared keys are not indentical" + "\n");
	    };







	    //Encrypted data exchange 1
	    String fixedmessagetosend1 = "Hi how are you??";
	    System.out.println("Sending encrypted message:" + fixedmessagetosend1);
	    String sessionIDstr = String.valueOf(sessionID);
	    BigInteger sessionIDhashed = functions.sha256(sessionIDstr);
	    String encrypted = functions.Encrypt(fixedmessagetosend1, sessionIDhashed);
	    oos.writeObject(encrypted);
`		
		System.out.println("\n" + "Sent encrypted form: " + encrypted[0] + "\n");

		//Calculating HMAC
	    String Hmacmessage = functions.HMAC(sessionIDstr, fixedmessagetosend1).toString();

	    //Sending HMAC for verification
		oos.writeObject(Hmacmessage);

//-------------------------------------------------------------------------------------------------------------------------------
		    System.out.println("Initiating Authentication for second message transmission..." + "\n");


		 //Sending RSA public key
	    System.out.println("Sent to Client: ");
	     rsapk = "RSA_PK: " + publicKey.toString();
	    System.out.println("7. " + rsapk + " and RSA value n (large prime numbers p and g multipied together)");
	    oos.writeObject(publicKey.toString());
	     n = functions.getN();
	    oos.writeObject(n);
	    System.out.println("Client <---------------------- Server" + "\n");

	     

	 	//generate and store RSA private key
	    d = functions.getD(publicKey);
	    System.out.println("RSA Private Key has been generated.");

	    //Generate and send RSA signature
	    
		sig = functions.DigitalSignature(serverID, publicKey);
		System.out.println("Digitial Signature created" + "\n");		
		oos.writeObject(sig);

		//generate DHprivate key
		DHpriv = functions.calcDHPrivKey();

		//generate DH public key
		DHpub = functions.calcDHpublicKey(DHpriv);


		//Sending DH public key
		System.out.println("Sent to Client: ");
	    oos.writeObject(DHpub);
	    oos.writeObject(sig);
	    System.out.println("8. Server Diffie Helman public key. ");
	    System.out.println("Client ----------------------> Server" + "\n");

	    //Reiceving Client DH public key
	    System.out.println("Client sent: ");
	    clientDHpub = new BigInteger(String.valueOf(ois.readObject()));
	    System.out.println("9. Client Diffie Helman public key. ");
	    System.out.println("Client ----------------------> Server" + "\n");



	    //Calculating DH shared key
	    DHsharedkey = functions.calcDHsharedKey(clientDHpub, DHpriv, sessionID);

	          //Key confirmation
	    shareddhstr = String.valueOf(DHsharedkey);
	    serverDHverify = functions.sha256(shareddhstr);
	    oos.writeObject(serverDHverify);
	    clientverify = new BigInteger(String.valueOf(ois.readObject()));
	    if(clientverify.equals(serverDHverify))
	    {
	      	System.out.println("Shared keys confirmed to be indentical" + "\n");
	    }else{
	      	System.out.println("Shared keys are not indentical" + "\n");
	    };



//-------------------------------------------------------------------------------------------------------------------------------


		//Encrypted data exchange 2
		String fixedmessagetosend2 = "secretmessage123";
	    System.out.println("Sending encrypted message:" + fixedmessagetosend2);
	    String encrypted2 = functions.Encrypt(fixedmessagetosend2, sessionIDhashed);
	    oos.writeObject(encrypted2);
		System.out.println("\n" + "Sent encrypted form: " + encrypted2 + "\n");

		//Calculating HMAC
	    String Hmacmessage2 = functions.HMAC(sessionIDstr, fixedmessagetosend2).toString();

	    //Sending HMAC for verification
		oos.writeObject(Hmacmessage2);



		System.out.println("-------------------------------------------------------------" + "\n");

    }
    
}

