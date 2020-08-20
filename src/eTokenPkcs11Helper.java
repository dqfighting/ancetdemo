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

/** 
 * This class is tightly coupled with the eTokenWrapper.dll
 * Do not change the package name nor the class name.
 */

import java.io.*;
import java.net.URL;
import java.security.*;
import java.util.ArrayList;
import java.util.Calendar;

/**
 * Helper class name to load SafeNet PKCS11 provider.
 * @author SafNet
 */
public final class eTokenPkcs11Helper {

	/** Number of slots to register	*/
	public static final int PKCS11_SLOTS = 4;
	/** SafeNet PKCS11 provider dll */
	public static final String eTPKCS11 = "eTPKCS11.dll";
	/** Holds the status of the registration */
	private Boolean m_bRegistered = false;
		
	/**
	 * Pre-register the provider
	 * @return true on success
	 */
	public boolean registerProvider()
	{
		Boolean bOk = m_bRegistered;
		try {
			if (!bOk)
			{
				System.out.println("Regisetering SafeNet provider...");
				String processType = System.getProperty("sun.arch.data.model");
				File eTPKCS11_File = new File("C:\\Windows\\System32\\" + eTPKCS11);
				for (int i=0;i<PKCS11_SLOTS; i++)
				{
					String pkcs11config =
							   "name = eToken_slot"+i+"\n" +
							   "library = " + eTPKCS11_File.getCanonicalPath() + "\n"+
							   "slot = "+i+"\n";
			
					byte[] pkcs11configBytes = pkcs11config.getBytes();
					ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11configBytes);
					Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(configStream);
					System.out.println("Provider:"+pkcs11Provider.getInfo());
					Security.addProvider(pkcs11Provider);					
				}
				m_bRegistered = true;
			}
		}catch(final Exception e) {
			e.printStackTrace();
		}
	 return bOk;
	}
	
	/**
	 * Retrieve a registered instance of the SafeNet PKCS11 provider
	 * by spesifc slot.
	 * @param slot requested slot.
	 * @return Provider object on success, null otherwise
	 */
	public Provider getProvider(int slot)
	{
		Provider pkcs11Provider = null;
		
		try {			
			if (!m_bRegistered)
			{
				AccessController.doPrivileged(new PrivilegedAction<Object>() {
					public Object run() {
						registerProvider();
						return null;
					};
				});
			}
			if (m_bRegistered)
			{
				pkcs11Provider = Security.getProvider("SunPKCS11-eToken_slot"+slot);
				if (pkcs11Provider!=null)
				{
					System.out.println("Found Provider:"+pkcs11Provider.getInfo());
				}
				else
				{
					System.out.println("Provider not found");
				}
			}
			
		}catch(final Exception e) {
			e.printStackTrace();
		}
		
		return pkcs11Provider;
	}
	
}
