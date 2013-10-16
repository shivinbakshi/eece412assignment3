package pckg;
import gnu.crypto.key.IKeyAgreementParty;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.Panel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.logging.Handler;

import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.xml.bind.DatatypeConverter;



public class UserInterface extends JFrame{
	
	private static final long serialVersionUID = 1L;
	private int portNumber;
	private ServerSocket serverSocket;
	private Socket clientSocket;
	private Socket connectionSocket;
	private String receivedText;
	private Handler handler;
	/* Views for the UI. */
	private JRadioButton btnClientMode = new JRadioButton("Client");
	private JRadioButton btnServerMode = new JRadioButton("Server");
	
	protected boolean serverMode = false;
	protected boolean clientMode = false;
	
	private JButton btnConnect = new JButton("Connect");
	private JButton btnDisconnect = new JButton("Disconnect");
	private JButton btnShare = new JButton("Share");
	
	private JButton btnSend = new JButton("Send");
	private JButton btnClear = new JButton("Clear");
	private JButton btnQuit = new JButton("Quit");
	
	private JLabel modeLabel = new JLabel(" Mode:");
	private JLabel hostLabel = new JLabel(" Host:");
	private JTextField hostField = new JTextField("", 20);
	private JLabel portLabel = new JLabel(" Port: ");
	private JTextField portField = new JTextField("5001", 20);
	
	private JLabel secretLabel = new JLabel(" Shared Secret Value:");
	private JTextField secretField = new JTextField("", 40);
	private JLabel dataLabel = new JLabel(" Data to be Sent:");
	private JTextArea dataField = new JTextArea(10, 30);
	private JLabel receivedLabel = new JLabel(" Data as Received: ");
	private JTextArea receivedField = new JTextArea(10, 30);
	
	private JLabel authLabel = new JLabel(" Authentication Status: ");
	private JLabel authStatus = new JLabel(" No Authentication");
	
	/* Key agreement variables. */
	protected KeyPair kp;
	protected IKeyAgreementParty ikap;
	protected Map map;
	protected byte[] k;
	protected boolean authenticated = false;
	
	/* RSA variables. */
	protected PrivateKey privateKey;
	protected PublicKey publicKey;
	protected PublicKey partnerPublicKey;
	
	public UserInterface(){
		super("Simple Virtual Private Network");
		
		/* Panels for holding the views. */
		JPanel modePanel = new JPanel(new GridLayout(1, 0));
		JPanel hostPanel = new JPanel(new BorderLayout());
		JPanel portPanel = new JPanel(new BorderLayout());
		JPanel secretPanel = new JPanel(new BorderLayout());
		JPanel dataPanel = new JPanel(new BorderLayout());
		JPanel receivedPanel = new JPanel(new BorderLayout());
		JPanel authPanel = new JPanel(new BorderLayout());
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		
		modePanel.add(modeLabel, BorderLayout.WEST);
		hostPanel.add(hostLabel, BorderLayout.WEST);
		hostPanel.add(hostField, BorderLayout.CENTER);
		portPanel.add(portLabel, BorderLayout.WEST);
		portPanel.add(portField, BorderLayout.CENTER);
		secretPanel.add(secretLabel, BorderLayout.NORTH);
		secretPanel.add(secretField, BorderLayout.CENTER);
		secretPanel.add(btnShare, BorderLayout.EAST);
		dataPanel.add(dataLabel, BorderLayout.NORTH);
		dataPanel.add(dataField, BorderLayout.CENTER);
		receivedPanel.add(receivedLabel, BorderLayout.NORTH);
		receivedPanel.add(receivedField, BorderLayout.CENTER);
		authPanel.add(authLabel, BorderLayout.WEST);
		authPanel.add(authStatus, BorderLayout.CENTER);
		
		/* Setting radio button listener. */
		btnClientMode.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				if(btnClientMode.isSelected()){
					hostField.setEnabled(true);
					hostField.setText("localhost");
					btnConnect.setText("Connect");
					authLabel.setText(" Server Authentication Status: ");
					if(serverMode)
						try {
							serverSocket.close();
						} catch (IOException e1) {
							e1.printStackTrace();
						} catch (Exception e2){
							
						}
					serverMode = false;
					clientMode = true;
				}
			}
		});
		
		btnServerMode.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				if(btnServerMode.isSelected()){
					hostField.setText("");
					hostField.setEnabled(false);
					btnConnect.setText("Listen");
					authLabel.setText(" Clent Authentication Status: ");
					serverMode = true;
					clientMode = false;
				}
				
			}
		});
		
		ButtonGroup group = new ButtonGroup();
		group.add(btnClientMode);
		group.add(btnServerMode);
		
		modePanel.add(btnServerMode);
		modePanel.add(btnClientMode);
		
		/* Setting button listeners. */
		
		btnConnect.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e){
				if(clientMode){
					clientSideAuthentication cs = new clientSideAuthentication();
					new Thread(cs).start();
					
/*					try {
						 Do authentication here. 
						clientSocket = new Socket(hostField.getText().toString(), Integer.parseInt(portField.getText().toString()));
						DataOutputStream toServer = new DataOutputStream(clientSocket.getOutputStream());
						toServer.writeBytes("Client Connection Received");
						clientSocket.close();
					} catch (NumberFormatException e1) {
						e1.printStackTrace();
					} catch (UnknownHostException e1) {
						e1.printStackTrace();
					} catch (IOException e1) {
						e1.printStackTrace();
					} */
				}
				else if(serverMode){
					// First authentication. Then if authenticated, start server thread
					serverSideAuthentication ss = new serverSideAuthentication();
					new Thread(ss).start();
					
					
			//		activeServer s = new activeServer();
			//		new Thread(s).start();
				}
			}
		});
		
		btnDisconnect.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e){
				
			}
		});
		
		btnShare.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e){
				
			}
		});
		
		btnSend.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				if(serverMode){
					try {
						DataOutputStream toClient = new DataOutputStream(connectionSocket.getOutputStream());
						toClient.writeBytes(dataField.getText());
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				}
				else if(clientMode){
					try {
						clientSocket = new Socket(hostField.getText().toString(), Integer.parseInt(portField.getText().toString()));
						DataOutputStream toServer = new DataOutputStream(clientSocket.getOutputStream());
						toServer.writeChars(dataField.getText());
						clientSocket.close();
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}
		});
		
		btnClear.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e){
				if(clientMode)
					hostField.setText("localhost");
				portField.setText("");
				secretField.setText("");
				receivedField.setText("");
			}
		});
		
		btnQuit.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e){
				System.exit(0);
			}
		});
		
		/* Panel for holding connect/disconnect buttons. */
		JPanel btnPanel1 = new JPanel(new GridLayout(1, 0));
		btnPanel1.add(btnConnect);
		btnPanel1.add(btnDisconnect);
		
		/* Panel for holding the bottom panel buttons. */
		JPanel btnPanel2 = new JPanel(new GridLayout(1, 0));
		btnPanel2.add(btnSend);
		btnPanel2.add(btnClear);
		btnPanel2.add(btnQuit);
		
		/* Add, pack and show. */
		Panel fieldPanel = new Panel(new GridLayout(0, 1));
		fieldPanel.add(modePanel);
		fieldPanel.add(hostPanel);
		fieldPanel.add(portPanel);
		fieldPanel.add(btnPanel1);
		
		add(fieldPanel, BorderLayout.NORTH);
		mainPanel.add(authPanel);
		mainPanel.add(secretPanel);
		mainPanel.add(dataPanel);
		mainPanel.add(receivedPanel);
		add(mainPanel);
		add(btnPanel2, BorderLayout.SOUTH);
		pack();
		setVisible(true);
	}
	
	private class activeServer implements Runnable{
		
		public activeServer(){};
		
		@Override
		public void run(){
				try {
					System.out.println("Starting Server");
					portNumber = Integer.parseInt(portField.getText().toString());
					serverSocket = new ServerSocket(portNumber);
				//	Socket connectionSocket = serverSocket.accept();
					while(serverMode){
						connectionSocket = serverSocket.accept();
						BufferedReader inFromClient = 
								new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
						receivedText = inFromClient.readLine();
						System.out.println("Received Text: " + receivedText);
						receivedField.setText(receivedText);
					}
				}
				catch(BindException e){
					
				}
				catch (IOException e1) {
					e1.printStackTrace();
				} 
		}
	};
	
	private class serverSideAuthentication implements Runnable{
		@Override
		public void run(){
			System.out.println("1. Server Side - Starting client authentication");
			portNumber = Integer.parseInt(portField.getText());
			try {
				serverSocket = new ServerSocket(portNumber);
				connectionSocket = serverSocket.accept();
				DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
				DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
				
//---------------------------------------------------------------------------------------------------------
//				AUTHENTICATION
//---------------------------------------------------------------------------------------------------------				
				/** RETREIVE CLIENT'S PUBLIC KEY. **/
	            byte[] lenb = new byte[4];
	            do{
	            	System.out.println("Waitng for client public key.");
	            }while(connectionSocket.getInputStream() == null);
	            inFromClient.read(lenb,0,4);
	            ByteBuffer bb = ByteBuffer.wrap(lenb);
	            int len = bb.getInt();
	            System.out.println(len);
	            byte[] servPubKeyBytes = new byte[len];
	            inFromClient.read(servPubKeyBytes);
	            System.out.println(DatatypeConverter.printHexBinary(servPubKeyBytes));
	            X509EncodedKeySpec ks = new X509EncodedKeySpec(servPubKeyBytes);
	            KeyFactory kf = KeyFactory.getInstance("RSA");
	            partnerPublicKey = kf.generatePublic(ks);
	            System.out.println("Client Public Key: " + partnerPublicKey);
	            System.out.println(DatatypeConverter.printHexBinary(partnerPublicKey.getEncoded()));
	            
	            /** SEND PUBLIC KEY TO CLIENT. **/
				System.out.println("***Sending public key to client.*** ");
				ByteBuffer bb2 = ByteBuffer.allocate(4);
				bb2.putInt(publicKey.getEncoded().length);
				outToClient.write(bb2.array());
				outToClient.write(publicKey.getEncoded());
				outToClient.flush();
//---------------------------------------------------------------------------------------------------------	
							
				/** RECEIVE AUTHENTICATION REQUEST MESSAGE AND NONCE. **/
				System.out.println("Server - Waiting for client request");
				String clientAuthRequest = inFromClient.readLine();
				System.out.println("Received From Client: " + clientAuthRequest);
				
				/** SENDING NONCE AND SESSION KEY(?) SIGNED AND ENCRYPTED**/
				System.out.println("Sending to Client");
				String nonce = clientAuthRequest.substring(12, clientAuthRequest.length());
				// Signing nonce and session key
				String n_a_k = nonce + "SessionKey";
				// Signing with private RSA key
				byte[] signed_n_a_k = RSA.sign(n_a_k, privateKey);
				// Ecrypting with client's public RSA key
				String encrypted_signed_n_a_k = new String(signed_n_a_k);
				byte[] encrypted_signed_n_a_k_bytes = RSA.rsaEncrypt(signed_n_a_k, partnerPublicKey);
				System.out.println("N_A_K Size: " + encrypted_signed_n_a_k_bytes.length);
				
			//	outToClient.write(encrypted_signed_n_a_k_bytes);
				//outToClient.writeBytes(encrypted_signed_n_a_k_bytes + "\n"); 
				
				
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
	}
	
	private class clientSideAuthentication implements Runnable {
		@Override
		public void run(){
			System.out.println("2. Client Side - Starting server authentication");
			try {	
				clientSocket = new Socket(hostField.getText().toString(), Integer.parseInt(portField.getText()));
				DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
				DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
//---------------------------------------------------------------------------------------------------------
//				AUTHENTICATION
//---------------------------------------------------------------------------------------------------------				
				/** SEND PUBLIC KEY TO SERVER. **/
				System.out.println("***Sending public key to server.***");
				ByteBuffer bb = ByteBuffer.allocate(4);
				bb.putInt(publicKey.getEncoded().length);
				outToServer.write(bb.array());
				outToServer.write(publicKey.getEncoded());
				outToServer.flush();
				
				/** RETRIEVE SERVER'S PUBLIC KEY. ***/
	            byte[] lenb = new byte[4];
	            do{
	            	System.out.println("Waiting for server's public key.");
				}while(clientSocket.getInputStream() == null);
	            inFromServer.read(lenb,0,4);
	            ByteBuffer bb2 = ByteBuffer.wrap(lenb);
	            int len = bb2.getInt();
	            System.out.println(len);
	            byte[] servPubKeyBytes = new byte[len];
	            inFromServer.read(servPubKeyBytes);
	            System.out.println(DatatypeConverter.printHexBinary(servPubKeyBytes));
	            X509EncodedKeySpec ks = new X509EncodedKeySpec(servPubKeyBytes);
	            KeyFactory kf = KeyFactory.getInstance("RSA");
	            partnerPublicKey = kf.generatePublic(ks);
	            System.out.println("Server Public Key: " + partnerPublicKey);
	            System.out.println(DatatypeConverter.printHexBinary(partnerPublicKey.getEncoded()));
//---------------------------------------------------------------------------------------------------------				

	            // SENDING NONCE AND REQUEST MESSAGE
				System.out.println("Writing to Server");
				outToServer.writeBytes("SecureClient" + RSA.genNonce() + "\n"); 
				
				/** RECEIVE NONCE AND SESSION KEY FROM SERVER. **/
				System.out.println("Client - Waiting for nonce and session key");
				byte[] serverResponse = new byte[10];
				inFromServer.readFully(serverResponse);
				System.out.println("Received From Server: " + serverResponse);
				
				
				
			//	outToServer.close();
			//	inFromServer.close();
				clientSocket.close();
			} catch (NumberFormatException e) {
				e.printStackTrace();
			} catch (UnknownHostException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public class sendPublicKey implements Runnable {
		@Override
		public void run(){
			
		}
	}
	

}
