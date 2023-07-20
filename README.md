# AES_SSLHANDSHAKE

READ ME:

This is a simulated Client Server interaction in java showcasing an SSL Handshake including including : Fast Modular exponentiation, RSA signature scheme, Diffie-Helman Key exchange,HMAC, CBC mode AES encryption.


Diagram of program flow:

Client - - - - - - - - - - - - - - - - - - - - Server

		Setup_Request: Hello
	 --------------------------------->

            Setup: Server's RSA Public key
	  <---------------------------------

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

		Client_Hello: ID c
	  --------------------------------->        
                                                
		Server_Hello: ID s, SID
	  <--------------------------------- 	     
						                             
		Ephemeral DH exchange		      
	  <--------------------------------->	       
						                                 
	    Finished, check the shared key
	  <--------------------------------->

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

	            Data exchange
	  <--------------------------------->



To run please compile server.java, client.java and functions.java

Run Client.java and Server.java files seperately

Follow on screen Instructions when needed

And be patient with the calculations, as the program is not instanaous.

Thank you :)
