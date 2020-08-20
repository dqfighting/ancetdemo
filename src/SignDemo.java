////////////////////////////////////////////////////////////////////////////////////////////
// Copyright 2011 by SafeNet, Inc., (collectively herein  "SafeNet"), Belcamp, Maryland
// All Rights Reserved
// The SafeNet software that accompanies this License (the "Software") is the property of
// SafeNet, or its licensors and is protected by various copyright laws and international
// treaties.
// While SafeNet continues to own the Software, you will have certain non-exclusive,
// non-transferable rights to use the Software, subject to your full compliance with the
// terms and conditions of this License.
// All rights not expressly granted by this License are reserved to SafeNet or
// its licensors.
// SafeNet grants no express or implied right under SafeNet or its licensors� patents,
// copyrights, trademarks or other SafeNet or its licensors� intellectual property rights.
// Any supplemental software code, documentation or supporting materials provided to you
// as part of support services provided by SafeNet for the Software (if any) shall be
// considered part of the Software and subject to the terms and conditions of this License.
// The copyright and all other rights to the Software shall remain with SafeNet or 
// its licensors.
// For the purposes of this Agreement SafeNet, Inc. includes SafeNet, Inc and all of
// its subsidiaries.
//
// Any use of this software is subject to the limitations of warranty and liability
// contained in the end user license.
// SafeNet disclaims all other liability in connection with the use of this software,
// including all claims for  direct, indirect, special  or consequential regardless
// of the type or nature of the cause of action.
////////////////////////////////////////////////////////////////////////////////////////////



import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import javax.security.auth.login.LoginException;

/**
 * This demo uses SafeNet PKCS11 provider for signing a binary
*  note: The Java-SunPKCS11Wrapper doesn't work with HID tokens.
 * @author SafNet
 */
public class SignDemo
{
    /** Holds the name of the binary to sign - in this demo we are using eToken.dll */
	public static final String BINARY_TO_SIGN = "C:\\Windows\\System32\\eToken.dll";
	private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
    private static final String X509_CERTIFICATE_TYPE = "X.509";
    private static final String CERTIFICATION_CHAIN_ENCODING = "PkiPath";
    private static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";

	/**
	 * Main function. Reads a binary file {@link #BINARY_TO_SIGN} and displays 
	 * its signature on the console.
	 * @param args Not used
	 */
	public static void main(String[] args) 
	{   
		// token pin code - we are using empty - so SafeNet token login dialog will be shown.
		String pinCode = "";
		
		try {
			// Load the file for signing
			byte[] documentToSign = null;
			documentToSign = readFileInByteArray(BINARY_TO_SIGN);
		
			// sign the given file
			CertificationChainAndSignatureBase64 signingResult = signDocument(documentToSign, pinCode);
			System.out.println("Signature: "+signingResult.mSignature);
			
			// verify the given file with the signature we just got. This verification is done on the software using the certificat ewe loaded.
			// The token us not being accees at this point.
			boolean bVerified = verifyDocumentSignature(signingResult.mCertificationChain, documentToSign, signingResult.mSignature);
			if (bVerified)
			{
				System.out.println("Signature verified successfully");
			}
		}
		catch (IOException ioex) {
             System.out.println("Can not read the file for signing " + BINARY_TO_SIGN + ".");			
        }
        catch (DocumentSignException dse) {
            // Document signing failed. Display error message
			System.out.println(dse.getMessage());
        }
        catch (SecurityException se) {            
			System.out.println("Unable to access the local file system.\n" +
							   "This applet should be started with full security permissions.\n" +
							   "Please accept to trust this applet when the Java Plug-In ask you.");
        }       
        catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
        }
	}
	
	/**
     * Signs given docoment. The certificate and private key to be used for signing
     * come from the locally attached smart card.
     * @param aDocumentToSign document contact to sign.
	 * @param aPinCode smartcard pin code.
     * @return the digital signature of the given file and the certification chain of
     * the certificatie used for signing the file, both Base64-encoded or null if the
     * signing process is canceled by the user.
     * @throws DocumentSignException when a problem arised during the singing process
     * (e.g. smart card access problem, invalid certificate, invalid PIN code, etc.)
     */
	private static CertificationChainAndSignatureBase64 signDocument(
        byte[] aDocumentToSign, String aPinCode)
    throws DocumentSignException {
        // Load the keystore from the smart card using the specified PIN code
        KeyStore userKeyStore = null;
        try {
            userKeyStore = loadKeyStoreFromSmartCard(aPinCode);
        } catch (Exception ex) {
            String errorMessage = "Can not read the keystore from the smart card.\n" +
                "Possible reasons:\n" +
                " - The smart card reader in not connected.\n" +
                " - The smart card is not inserted.\n" +
                " - The PKCS#11 implementation library is invalid.\n" +
                " - The PIN for the smart card is incorrect.\n" +
                "Problem details: " + ex.getMessage();
            throw new DocumentSignException(errorMessage, ex);
        }

        // Get the private key and its certification chain from the keystore
        PrivateKeyAndCertChain privateKeyAndCertChain = null;
        try {
            privateKeyAndCertChain =
                getPrivateKeyAndCertChain(userKeyStore);
        } catch (GeneralSecurityException gsex) {
            String errorMessage = "Can not extract the private key and " +
                "certificate from the smart card. Reason: " + gsex.getMessage();
            throw new DocumentSignException(errorMessage, gsex);
        }

        // Check if the private key is available
        PrivateKey privateKey = privateKeyAndCertChain.mPrivateKey;
        if (privateKey == null) {
            String errorMessage = "Can not find the private key on the smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Check if X.509 certification chain is available
        Certificate[] certChain = privateKeyAndCertChain.mCertificationChain;
        if (certChain == null) {
            String errorMessage = "Can not find the certificate on the smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Create the result object
        CertificationChainAndSignatureBase64 signingResult =
            new CertificationChainAndSignatureBase64();

        // Save X.509 certification chain in the result encoded in Base64
        try {
            signingResult.mCertificationChain = encodeX509CertChainToBase64(certChain);
        }
        catch (CertificateException cee) {
            String errorMessage = "Invalid certificate on the smart card.";
            throw new DocumentSignException(errorMessage);
        }

        // Calculate the digital signature of the file,
        // encode it in Base64 and save it in the result
        try {
            byte[] digitalSignature = signDocument(aDocumentToSign, privateKey);
            signingResult.mSignature = Base64Utils.base64Encode(digitalSignature);
        } catch (GeneralSecurityException gsex) {
            String errorMessage = "File signing failed.\n" +
                "Problem details: " + gsex.getMessage();
            throw new DocumentSignException(errorMessage, gsex);
        }

        try
        {
        	AuthProvider authProvider = (AuthProvider) userKeyStore.getProvider();
        	authProvider.logout();
        } catch (LoginException e) {
        	String errorMessage = "Failed loagout.\n" +
            "Problem details: " + e.getMessage();
        throw new DocumentSignException(errorMessage, e);
        }
        return signingResult;
    }
	
	/**
	 * Verifies a documnet signature using a public key certificate - which was loaded from the token.
	 * <p>
	 * This function does the verification on the software (using SUN API) and not on the token.
	 * @param publicKeyCertificate public key certificate that was loaded from the token.
	 * @param documentToVerify byte array representation of the binary to verify.
	 * @param signature the signature for the verification.
	 * @return true if the the verification passed.  
	 * @throws DocumentSignException when a problem arised during the verification process (e.g. the verification failed).
   	 */
	private static boolean verifyDocumentSignature(String encoedCertificationChain, byte[] documentToVerify, String signature)
	throws DocumentSignException {
		try{
			// decode the base 64 signature we got
			byte[] digitalSignature = Base64Utils.base64Decode(signature);
			
			// create a certifcate form the byte array certificate we load from the the token at the begining.
			Certificate[] certificationChain = decodeX509CertChainToBase64(encoedCertificationChain);
			//X509Certificate certificate = (X509Certificate)certificationChain[0];
			/*
			CertificateFactory certificateFactory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);						
			byte[] encodedCertificate = publicKeyCertificate.getValue().getByteArrayValue();				
			X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(encodedCertificate));
			*/
			// Initialize the signature 
			Signature signatureEngine = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME);			
			signatureEngine.initVerify(certificationChain[0].getPublicKey());	
			// load the binary
			signatureEngine.update(documentToVerify);
			
			
			try {
				// try to verify 
				if (signatureEngine.verify(digitalSignature)) {              
					return true;
					} else {
					throw(new DocumentSignException("Signature Invalid.") );
				}
				} catch (SignatureException ex) {
				throw(new DocumentSignException("Verification FAILED: " + ex.getMessage()));
			}
		} catch (Exception ex)
		{
			ex.printStackTrace();
			throw new DocumentSignException(ex.getMessage());
		}
	}

    /**
     * Loads the keystore from the smart card using its PKCS#11 implementation
     * library and the Sun PKCS#11 security provider. The PIN code for accessing
     * the smart card is required.
	 * @param aSmartCardPIN PIN code for accessing the smart card
	 * @throws GeneralSecurityException when a problem arised during the smartcard access
	 * @throws IOException when a problem arised during the smartcard access
     */
    private static KeyStore loadKeyStoreFromSmartCard(String aSmartCardPIN)
    throws GeneralSecurityException, IOException {
        

        KeyStore smartCardKeyStore = null;
        
		// get the SafeNet provider		
		eTokenPkcs11Helper helper = new eTokenPkcs11Helper();
		helper.registerProvider();
		
		Provider pkcs11Provider = null;
		//Uncomment the folowing lines to force using a spesifc slot
		//Provider pkcs11Provider = helper.getProvider(0);
		//if (pkcs11Provider == null)
		//{
			//return null;
		//}
		
		//use SafeNet UI for store login ("" - will result in login screen)
		KeyStore.ProtectionParameter pin = new KeyStore.PasswordProtection(aSmartCardPIN.toCharArray());
		KeyStore.Builder builder = KeyStore.Builder.newInstance(PKCS11_KEYSTORE_TYPE, pkcs11Provider, pin);
		
		//logs it to store
		smartCardKeyStore = builder.getKeyStore();
			
		return smartCardKeyStore;
    }

    /**
	 * Get the private key and its certification chain from the keystore.
	 * The keystore is considered to have only one entry that contains
     * both certification chain and its corresponding private key. If the keystore has
     * no entries, an exception is thrown.
	 * @param aKeyStore ketystore referance
     * @return private key and certification chain corresponding to it, extracted from
     * given keystore. 	 
	 * @throws GeneralSecurityException when a problem arised during the smartcard access
     */
    private static PrivateKeyAndCertChain getPrivateKeyAndCertChain(
        KeyStore aKeyStore)
    throws GeneralSecurityException {      
		Enumeration aliasesEnum = aKeyStore.aliases();
        if (aliasesEnum.hasMoreElements()) {
            String alias = (String)aliasesEnum.nextElement();			
            Certificate[] certificationChain = aKeyStore.getCertificateChain(alias);
            PrivateKey privateKey = (PrivateKey) aKeyStore.getKey(alias, null);
            PrivateKeyAndCertChain result = new PrivateKeyAndCertChain();
            result.mPrivateKey = privateKey;
            result.mCertificationChain = certificationChain;
            return result;
        } else {
            throw new KeyStoreException("The keystore is empty!");
        }
    }

    /**
	 * Create Base64 representation of X.509 certification chain 
	 * @param aCertificationChain a referance to the certificate chain
     * @return Base64-encoded ASN.1 DER representation of given X.509 certification
     * chain.
	 * @throws CertificateException when the cerifciate is invalid
     */
    private static String encodeX509CertChainToBase64(Certificate[] aCertificationChain)
    throws CertificateException {
        List certList = Arrays.asList(aCertificationChain);
        CertificateFactory certFactory =
            CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        CertPath certPath = certFactory.generateCertPath(certList);
        byte[] certPathEncoded = certPath.getEncoded(CERTIFICATION_CHAIN_ENCODING);
        String base64encodedCertChain = Base64Utils.base64Encode(certPathEncoded);
        return base64encodedCertChain;
    }
	
	/**
	 * Create Base64 representation of X.509 certification chain 
	 * @param aCertificationChain a referance to the certificate chain
     * @return Base64-encoded ASN.1 DER representation of given X.509 certification
     * chain.
	 * @throws CertificateException when the cerifciate is invalid
     */
    private static Certificate[] decodeX509CertChainToBase64(String base64encodedCertChain)
    throws CertificateException {
		byte[] decodedCertificationChain = Base64Utils.base64Decode(base64encodedCertChain);
		ByteArrayInputStream is = new ByteArrayInputStream(decodedCertificationChain);
		CertificateFactory certFactory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
		CertPath certPath = certFactory.generateCertPath(is, CERTIFICATION_CHAIN_ENCODING);
		List certs = certPath.getCertificates();
		Certificate[] certificationChain = new Certificate[certs.size()];
		for (int i=0; i<certs.size(); i++)
		{
			certificationChain[i] = (Certificate)certs.get(i);
		}
        return certificationChain;
    }

    /**
     * Reads the specified file into a byte array.
	 * @param aFileName name of the file to read.
	 * @return byte array representation on the given file.
	 * @throws IOException when file reading failed.
     */
    private static byte[] readFileInByteArray(String aFileName)
    throws IOException {
        File file = new File(aFileName);
        FileInputStream fileStream = new FileInputStream(file);
        try {
            int fileSize = (int) file.length();
            byte[] data = new byte[fileSize];
            int bytesRead = 0;
            while (bytesRead < fileSize) {
                bytesRead += fileStream.read(data, bytesRead, fileSize-bytesRead);
            }
            return data;
        }
        finally {
            fileStream.close();
        }
    }

    /**
     * Signs given document with a given private key.
	 * @param aDocument byte array representation of the documant to sign.
	 * @param aPrivateKey private key to use for signing.
	 * @return generatedsignature for the given documant.
     */
    private static byte[] signDocument(byte[] aDocument, PrivateKey aPrivateKey)
    throws GeneralSecurityException {
        Signature signatureAlgorithm =
            Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME);
        signatureAlgorithm.initSign(aPrivateKey);
        signatureAlgorithm.update(aDocument);
        byte[] digitalSignature = signatureAlgorithm.sign();
        return digitalSignature;
    }

    /**
     * Data structure that holds a pair of private key and
     * certification chain corresponding to this private key.
     */
    static class PrivateKeyAndCertChain {
        public PrivateKey mPrivateKey;
        public Certificate[] mCertificationChain;
    }

    /**
     * Data structure that holds a pair of Base64-encoded
     * certification chain and digital signature.
     */
    static class CertificationChainAndSignatureBase64 {
        public String mCertificationChain = null;
        public String mSignature = null;
    }

    /**
     * Exception class used for document signing errors.
     */
    static class DocumentSignException extends Exception {
      	private static final long serialVersionUID = 1L;

		public DocumentSignException(String aMessage) {
            super(aMessage);
        }

        public DocumentSignException(String aMessage, Throwable aCause) {
            super(aMessage, aCause);
        }
    }
}
