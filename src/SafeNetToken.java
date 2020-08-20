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
// SafeNet grants no express or implied right under SafeNet or its licensors锟� patents,
// copyrights, trademarks or other SafeNet or its licensors intellectual property rights.
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
import java.io.IOException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Module.WaitingBehavior;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;

/** Sample program for iaikPkcs11Wrapper usage with SafeNet tokens.
 * This demo show how to use iaikPkcs11Wrapper for generate RSA key pair in SafeNet token and sign a binary with this keys.
 * note: Please use CSP RSA certificate with Java-iaikPkcs11Wrapper sample.
 * <p>
 * The demo works as follow:
 * <ol>
 * <li>Reads a binary file (in this case eToken.dll).</li>
 * <li>Initialize iaikPkcs11Wrapper module.</li>
 * <li>Waits for token insertion event.</li>
 * <li>Generates RSA key pair in the SafeNet token.</li>
 * <li>Sign the binary using the private key and display the signature.</li>
 * <li>Verify the signature using the public key and display the verification results.</li>
 * </ol>
 * @author SafeNet                                            
 */
public class SafeNetToken
{
    private static final String PKCS11_WRAPPER = "pkcs11wrapper.dll";
	
    /** Holds the name of the binary to sign - in this demo we are using eToken.dll */
    public static final String BINARY_TO_SIGN = "C:\\Windows\\System32\\eToken.dll";
    private static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";	

    public static void main(String[] args) 
    {   
	Session session = null;
	
	// token pin code - we are using empty - so SafeNet token login dialog will be shown.
	String pinCode = "";
	try 
        {			
            // Load the file for signing
            byte[] documentToSign = null;
            documentToSign = readFileInByteArray(BINARY_TO_SIGN);			
		
            // find the currect OS architecture for loading the native wrapper
            String osArch = System.getProperty("os.arch");		
            File directory = new File (".");			
            Module pkcs11Module = Module.getInstance("eTPKCS11.dll", "C:/Windows/SysWOW64/"+PKCS11_WRAPPER);
            
            System.out.print("Initializing PKCS11 module:      ");
            pkcs11Module.initialize(null);
            System.out.println("OK");
            
            System.out.println("Please insert a SafeNet token...");			
            Token token = waitForTokenInsertion(pkcs11Module);
            if (token == null)
            {
		throw new DocumentSignException("We have no token to proceed. Finished.");
            }
		
            // open PKCS11 session to the connected token
            session = token.openSession( Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
		
            if (session != null)
            {
                KeyPair keys = GenKeyPair(session, pinCode);
			
                // sign the given file
                 byte[] signature = signDocument(session, keys.getPrivateKey(), documentToSign);
                            
                // encode it in Base64 and save it in the result       
                System.out.println("Signature: "+Base64Utils.base64Encode(signature));	

                // verify the given file with the signature we just got. This verification is done on the software using the certificat we loaded.
                // The token use not being accees at this point.
                if(verifyDocumentSignature(keys.getPublicKey(), documentToSign, signature))
                    System.out.println("Signature verified successfully");
                else
                    System.out.println("Signature verified failed");
            }
        }
        catch (IOException ioex) 
        {
            System.out.println("Can not read the file for signing " + BINARY_TO_SIGN + ".");		
        }
        catch (DocumentSignException dse) 
        {
            // Document signing failed. Display error message
            System.out.println(dse.getMessage());
        }
        catch (SecurityException se) 
        {            
            System.out.println("Unable to access the local file system.");
        }       
        catch (Exception e) 
        {
            System.out.println("Unexpected error: " + e.getMessage());
        }
        finally
        {
            // make sure we are closing the PKCS11 session.
            if (session != null)
            {
                try
                {
                    session.closeSession();
                }
                catch (TokenException ex){}
            }
        }
    }

    /**
    * Generate RSA key pair.
    * @param session PKCS11 session for working with the token.
    * @param pinCode user Pin Code.
    * @return RSA KeyPair.
    * @throws TokenException when a problem arise during the key generation process (e.g. smart card access problem).
    */
    private static KeyPair GenKeyPair(Session session, String pinCode) throws TokenException
    {
        try 
        {	
            session.login(Session.UserType.USER, pinCode.toCharArray()); 

            String keyName = "iaik.SafeNet";
            int keySize = 1024;

            RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
            privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
            privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE); // make it a persisten key on the token
            privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
            privateKeyTemplate.getLabel().setCharArrayValue(keyName.toCharArray());

            privateKeyTemplate.getKeyType().setPresent(false);
            privateKeyTemplate.getObjectClass().setPresent(false);
            privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
            privateKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);
            
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            publicKeyTemplate.getModulusBits().setLongValue(new Long(keySize));
            byte[] publicExponentBytes = {0x01, 0x00, 0x01};
            publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
            publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
            publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
            publicKeyTemplate.getLabel().setCharArrayValue(keyName.toCharArray());
            
            publicKeyTemplate.getKeyType().setPresent(false);
            publicKeyTemplate.getObjectClass().setPresent(false);
            publicKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);
            
            return session.generateKeyPair(Mechanism.RSA_PKCS_KEY_PAIR_GEN, publicKeyTemplate, privateKeyTemplate);
            
        }
        catch (TokenException ex) 
        {
            System.out.println("fail to generate RSA key pair.");		
            return null;
        }
    }
	
    /**
     * Demonstrate wait for slot event. Execution will be blocked until a token is inserted or removed.
     * @param pkcs11Module pkcs11 wrapper module. 
     * @return If a token was inserted then Token object is returned, else returns null.    
     * @throws TokenException when a problem arise during "waitForSlotEvent" or when trying to access the slot.
     */ 
    private static Token waitForTokenInsertion(Module pkcs11Module) throws TokenException
    {	
    	Slot slot = pkcs11Module.waitForSlotEvent( WaitingBehavior.BLOCK, null );
	Token token = slot.getToken();
	if (token == null) 
        {
            System.out.println("Token extraction event. Finished...");	  
            return null;
	}
        
	System.out.println("Token insertion - event occured.");
		
	return token;
    }
		
    /**
    * Signs a given document. The private key to be used for signing comes from the locally attached token.
    * @param session PKCS11 session for working with the token.
    * @param signatureKey private key for signing.
    * @param documentToSign byte array representation of the binary to sign. 
    * @return the digital signature of the given file - Base64-encoded.
    * @throws DocumentSignException when a problem arise during the singing process (e.g. smart card access problem).
    */
    private static byte[] signDocument(Session session, iaik.pkcs.pkcs11.objects.PrivateKey signatureKey, byte[] documentToSign ) throws DocumentSignException 
    {
        try
        {	
            Mechanism signatureMechanism = Mechanism.SHA256_RSA_PKCS;
            // initialize for signing
            session.signInit(signatureMechanism, signatureKey);		
                   
            // Calculate the digital signature of the file,
            return session.sign(documentToSign);
                    
        } 
        catch (Exception ex)
        {
            throw new DocumentSignException(ex.getMessage());
        }
    }

    /**
    * verify a given document. The public key to be used for signing comes from the locally attached token.
    * @param publicKey public key for verification.
    * @param documentToVerify byte array representation of the binary to verify. 
    * @return true on success else false.
    * @throws DocumentSignException when a problem arise during the verification process.
    */
    private static boolean verifyDocumentSignature(iaik.pkcs.pkcs11.objects.PublicKey publicKey, byte[] documentToVerify, byte[] digitalSignature) throws DocumentSignException 
    {
        try
        {
            //convert inik.pkcs.pkcs11 public key to java.security public key
            RSAPublicKey rsaPK = (RSAPublicKey)publicKey;
            BigInteger modulus = new BigInteger(rsaPK.getModulus().toString(), 16);
            BigInteger exponent = new BigInteger(rsaPK.getPublicExponent().toString(), 16);

            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pub = factory.generatePublic(spec);

            // Verifying the Digital Signature
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(pub);
            verifier.update(documentToVerify);

            if (verifier.verify(digitalSignature))
            {
                return true;
            }
        }
        catch (Exception ex)
        {
            throw new DocumentSignException(ex.getMessage());
        }

        return false;
    }

    /**
    * Reads the specified file into a byte array.
    * @param fileName name of the file to read.
    * @return byte array representation on the given file.
    * @throws IOException when file reading failed.
    */
    private static byte[] readFileInByteArray(String fileName) throws IOException 
    {
	File file = new File(fileName);
	FileInputStream fileStream = new FileInputStream(file);
	try 
        {
            int fileSize = (int) file.length();
            byte[] data = new byte[fileSize];
            int bytesRead = 0;
            while (bytesRead < fileSize) 
            {
		bytesRead += fileStream.read(data, bytesRead, fileSize-bytesRead);
            }
            return data;
	}
	finally 
        {
            fileStream.close();
	}
    }

    /**
    * Exception class used for document signing errors.
    */
    static class DocumentSignException extends Exception 
    {
	public DocumentSignException(String aMessage) 
        {
            super(aMessage);
	}
		
	public DocumentSignException(String aMessage, Throwable aCause) 
        {
            super(aMessage, aCause);
	}
    }
}
