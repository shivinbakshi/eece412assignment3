package pckg;

import gnu.crypto.Registry;
import gnu.crypto.key.IKeyPairGenerator;
import gnu.crypto.key.IncomingMessage;
import gnu.crypto.key.KeyAgreementException;
import gnu.crypto.key.KeyPairGeneratorFactory;
import gnu.crypto.key.OutgoingMessage;
import gnu.crypto.key.dh.DiffieHellmanKeyAgreement;
import gnu.crypto.key.dh.DiffieHellmanReceiver;
import gnu.crypto.key.dh.DiffieHellmanSender;
import gnu.crypto.key.rsa.RSAKeyPairGenerator;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

public class KeyAgreement {
	
	public KeyAgreement(){}
	
	public static void newDHAgreement(UserInterface server, UserInterface client){
		IKeyPairGenerator kpg = KeyPairGeneratorFactory.getInstance(Registry.DH_KPG);
		kpg.setup(new HashMap());
		client.kp = kpg.generate();
		server.kp = kpg.generate();
		client.ikap = new DiffieHellmanSender();
		server.ikap = new DiffieHellmanReceiver();
		
		client.map = new HashMap();
		client.map.put(DiffieHellmanKeyAgreement.KA_DIFFIE_HELLMAN_OWNER_PRIVATE_KEY,
				client.kp.getPrivate());
		System.out.println(client.map.get(DiffieHellmanKeyAgreement.KA_DIFFIE_HELLMAN_OWNER_PRIVATE_KEY));
		server.map = new HashMap();
		server.map.put(DiffieHellmanKeyAgreement.KA_DIFFIE_HELLMAN_OWNER_PRIVATE_KEY, 
				server.kp.getPrivate());
		System.out.println(server.map.get(DiffieHellmanKeyAgreement.KA_DIFFIE_HELLMAN_OWNER_PRIVATE_KEY));
		try {
			client.ikap.init(client.map);
			server.ikap.init(server.map);
			// (1) A -> B: g**x mod p
			OutgoingMessage out = client.ikap.processMessage(null);
			// (2) B -> A: g**y mod p
			out = server.ikap.processMessage(new IncomingMessage(out.toByteArray()));
			server.k = server.ikap.getSharedSecret();
			System.out.println("Server Key: " + server.k);
			// A computes the shared secret
			out = client.ikap.processMessage(new IncomingMessage(out.toByteArray()));
			client.k = client.ikap.getSharedSecret();
			System.out.println("Client Key: " + client.k);
		} catch (KeyAgreementException e) {
			e.printStackTrace();
		}
		
	}

	
}
