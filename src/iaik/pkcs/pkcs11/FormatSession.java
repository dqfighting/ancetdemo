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
// SafeNet grants no express or implied right under SafeNet or its licensors? patents,
// copyrights, trademarks or other SafeNet or its licensors? intellectual property rights.
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

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.SSL3KeyMaterialParameters;
import iaik.pkcs.pkcs11.parameters.SSL3MasterKeyDeriveParameters;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_SESSION_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SSL3_KEY_MAT_PARAMS;
import iaik.pkcs.pkcs11.wrapper.CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.util.Vector;



/**
 * Format session are used to create special hw objects on a token. The
 * application gets a Session object by calling etcInitTokenInit on a certain Token
 * object.
 *
 * @see iaik.pkcs.pkcs11.objects.Object
 * @see iaik.pkcs.pkcs11.parameters.Parameters
 * @see iaik.pkcs.pkcs11.Session
 * @see iaik.pkcs.pkcs11.SessionInfo
 * @author <a href="mailto:roman.bondatrevsky@safenet-inc.com"> Roman Bondarevsky </a>
 * @version 1.0
 * @invariants (pkcs11Module_ <> null)
 */
public class FormatSession extends Session {

  /**
   * Constructor taking the token and the sesion handle.
   *
   * @param token The token this session operates with.
   * @param sessionHandle The session handle to perform the operations with.
   * @preconditions (token <> null)
   * @postconditions
   */
  protected FormatSession(Token token, long sessionHandle)
  {
    super(token, sessionHandle);
  }

  /**
   * Create a special object in formatting session.
   * The application must provide a template
   * that holds enough information to create a certain object. 
   * 
   * @param templateObject The template object that holds all values that the
   *                       new object on the token should contain.
   *                       (this is not a java.lang.Object!)
   * @exception TokenException If the creation of the new object fails. If it
   *                           fails, the no new object was created on the
   *                           token.
   * @preconditions (templateObject <> null)
   * @postconditions (result <> null)
   */
  public Object createObject(Object templateObject)
      throws TokenException
  {
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(templateObject);
    long objectHandle = pkcs11Module_.C_CreateObject(sessionHandle_, ckAttributes);
    return new Object();
  }
}
