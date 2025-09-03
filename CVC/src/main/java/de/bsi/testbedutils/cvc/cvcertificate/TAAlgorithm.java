package de.bsi.testbedutils.cvc.cvcertificate;


/**
 * CVCA signature algorithm
 * @author meier.marcus
 * @version 1.0
 * @created 27-Aug-2009 14:19:55
 */
public enum TAAlgorithm {
	/**
	 * Undefined algorithm 
	 */
	UNDEFINED,
	/**
	 * RSA v1.5 with SHA 256 
	 */
	RSA_v1_5_SHA_256,
	/**
	 * RSA v1.5 with SHA 512
	 */
	RSA_v1_5_SHA_512,
	/**
	 * RSA PSS with SHA 256 
	 */
	RSA_PSS_SHA_256,
	/**
	 * RSA PSS with SHA 512
	 */
	RSA_PSS_SHA_512,
	/**
	 * ECC with SHA256 
	 */
	ECDSA_SHA_256,
	/**
	 * ECC with SHA512
	 */
	ECDSA_SHA_512;
	
	

}