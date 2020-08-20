import java.io.IOException;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;

public class testModel {

	public static void main(String[] args) throws Exception {
		final String PKCS11_WRAPPER = "pkcs11wrapper.dll";
		Module pkcs11Module = Module.getInstance("eTPKCS11.dll", "C:/Windows/SysWOW64/"+PKCS11_WRAPPER);
		pkcs11Module.initialize(null);
		try {
			Slot[] slotsWithToken = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
			for (int i = 0; i < slotsWithToken.length; i++) {
				System.out.println(slotsWithToken[i]);
			}
			System.out.println(slotsWithToken.length);
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
}
