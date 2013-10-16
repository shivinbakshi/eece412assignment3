package pckg;

public class Connect {
	
	private static UserInterface alice;
//	private static UserInterface bob;
	
	public Connect(){}
	
	public static void main(String args[]){
//		bob = new UserInterface();
//		RSA.generateRsaKeyPair(bob);
		alice = new UserInterface();
		RSA.generateRsaKeyPair(alice);		
	}
}
