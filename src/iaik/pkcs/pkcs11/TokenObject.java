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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.HardwareFeature;
import iaik.pkcs.pkcs11.objects.LongAttribute;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PQ;
import iaik.pkcs.pkcs11.objects.HardwareFeature.FeatureType;

import java.io.UnsupportedEncodingException;

/**
 * Objects of this class represent a token object as specified by PKCS#11 eSafe extension
 *
 * @author Roman Bondarevsky
 * @version 1.0
 * @invariants (value_ <> null)
 */
public class TokenObject extends HardwareFeature {

	/**
	 * The label of the token.
	*/
	protected CharArrayAttribute label_;
	
	protected BooleanAttribute has_lcd_;                
	protected BooleanAttribute has_so_;                 
	protected BooleanAttribute fips_;                   
	protected BooleanAttribute init_pin_req_;           
	protected BooleanAttribute rsa_2048_;               
	protected BooleanAttribute rsa_2048_supported_;     
	protected BooleanAttribute hmac_sha1_;              
	protected BooleanAttribute hmac_sha1_supported_;    
	protected BooleanAttribute real_color_;             
	protected BooleanAttribute may_init_;               
	protected BooleanAttribute mass_storage_present_;   
	protected BooleanAttribute mass_storage_secured_;   
	protected BooleanAttribute etoken_drive_;           
	protected BooleanAttribute one_factor_;             
	protected BooleanAttribute etv_temporary_;          
	protected BooleanAttribute fips_supported_;         
	protected BooleanAttribute override_retry_max_;     
	protected BooleanAttribute is_identrus_;            
	protected BooleanAttribute unblock_supported_;      
	protected BooleanAttribute reset_pin_supported_;    
	protected BooleanAttribute cc_;                     
	protected BooleanAttribute derive_unblock_from_so_; 
	protected BooleanAttribute minidriver_compatible_;  

	protected LongAttribute fw_revision_;           
	protected LongAttribute case_model_;            
	protected LongAttribute token_id_;              
	protected LongAttribute card_type_;             
	protected LongAttribute color_;                 
	protected LongAttribute retry_user_;            
	protected LongAttribute retry_so_;              
	protected LongAttribute retry_user_max_;        
	protected LongAttribute retry_so_max_;          
	protected LongAttribute fips_level_;            
	protected LongAttribute card_revision_;         
	protected LongAttribute pin_timeout_;           
	protected LongAttribute pin_timeout_max_;       
	protected LongAttribute crypto_lock_mode_;      
	protected LongAttribute crypto_lock_state_;     
	protected LongAttribute rsa_area_size_;         
	protected LongAttribute format_version_;        
	protected LongAttribute identrus_pin_age_;      
	protected LongAttribute user_pin_age_;          
	protected LongAttribute user_pin_iter_;         
	protected LongAttribute cardmodule_area_size_;  
	protected LongAttribute reserved_rsa_keys_1024_;
	protected LongAttribute reserved_rsa_keys_2048_;
	protected LongAttribute free_memory_;           
	protected LongAttribute unlock_count_;          
	protected LongAttribute unlock_max_;            

	protected CharArrayAttribute product_name_;   
	protected CharArrayAttribute model_;          
	protected CharArrayAttribute production_date_;
	protected CharArrayAttribute cc_certified_;   

	protected ByteArrayAttribute hw_internal_;            
	protected ByteArrayAttribute card_id_;                
	protected ByteArrayAttribute card_version_;           
	protected ByteArrayAttribute init_pki_version_;       
	protected ByteArrayAttribute clientless_version_;     
	protected ByteArrayAttribute os_release_version_;     
	protected ByteArrayAttribute hashval_;                
	protected ByteArrayAttribute os_name_;                
	protected ByteArrayAttribute puk_;                    
	protected ByteArrayAttribute import_pin_;             
	//protected ByteArrayAttribute secure_import_challenge_;

  /**
   * Default Constructor.
   *
   * @preconditions
   * @postconditions
   */
  public TokenObject() {
    super();
    hardwareFeatureType_.setLongValue(FeatureType.TOKEN_OBJECT);
   }

  /**
   * Called by getInstance to create an instance of a PKCS#11 pq.
   *
   * @param session The session to use for reading attributes.
   *                This session must have the appropriate rights; i.e.
   *                it must be a user-session, if it is a private object.
   * @param objectHandle The object handle as given from the PKCS#111 module.
   * @exception TokenException If getting the attributes failed.
   * @preconditions (session <> null)
   * @postconditions
   */
  protected TokenObject(Session session, long objectHandle)
      throws TokenException
  {
    super(session, objectHandle);
    hardwareFeatureType_.setLongValue(FeatureType.TOKEN_OBJECT);
  }

  /**
   * The getInstance method of the HardwareFeature class uses this method to
   * get an instance of a Safenet token object.
   *
   * @param session The session to use for reading attributes.
   *                This session must have the appropriate rights; i.e.
   *                it must be a user-session, if it is a private object.
   * @param objectHandle The object handle as given from the PKCS#111 module.
   * @return The object representing the PKCS#11 object.
   *         The returned object can be casted to the
   *         according sub-class.
   * @exception TokenException If getting the attributes failed.
   * @preconditions (session <> null)
   * @postconditions (result <> null) 
   */
  public static Object getInstance(Session session, long objectHandle)
      throws TokenException
  {
    return new TokenObject(session, objectHandle) ;
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately (see use in
   * clone()).
   *
   * @param object The object to handle.
   * @preconditions (object <> null)
   * @postconditions
   */
  protected static void putAttributesInTable(TokenObject object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.LABEL, object.label_);
    
    object.attributeTable_.put( Attribute.TO_HAS_LCD                , object.has_lcd_              );
    object.attributeTable_.put( Attribute.TO_HAS_SO                 , object.has_so_               );
    object.attributeTable_.put( Attribute.TO_FIPS                   , object.fips_                 );
    object.attributeTable_.put( Attribute.TO_INIT_PIN_REQ           , object.init_pin_req_         );
    object.attributeTable_.put( Attribute.TO_RSA_2048               , object.rsa_2048_             );
    object.attributeTable_.put( Attribute.TO_RSA_2048_SUPPORTED     , object.rsa_2048_supported_   );
    object.attributeTable_.put( Attribute.TO_HMAC_SHA1              , object.hmac_sha1_            );
    object.attributeTable_.put( Attribute.TO_HMAC_SHA1_SUPPORTED    , object.hmac_sha1_supported_  );
    object.attributeTable_.put( Attribute.TO_REAL_COLOR             , object.real_color_           );
    object.attributeTable_.put( Attribute.TO_MAY_INIT               , object.may_init_             );
    object.attributeTable_.put( Attribute.TO_MASS_STORAGE_PRESENT   , object.mass_storage_present_ );
    object.attributeTable_.put( Attribute.TO_MASS_STORAGE_SECURED   , object.mass_storage_secured_ );
    object.attributeTable_.put( Attribute.TO_ETOKEN_DRIVE           , object.etoken_drive_         );
    object.attributeTable_.put( Attribute.TO_ONE_FACTOR             , object.one_factor_           );
    object.attributeTable_.put( Attribute.TO_ETV_TEMPORARY          , object.etv_temporary_        );
    object.attributeTable_.put( Attribute.TO_FIPS_SUPPORTED         , object.fips_supported_       );
    object.attributeTable_.put( Attribute.TO_OVERRIDE_RETRY_MAX     , object.override_retry_max_   );
    object.attributeTable_.put( Attribute.TO_IS_IDENTRUS            , object.is_identrus_          );
    object.attributeTable_.put( Attribute.TO_UNBLOCK_SUPPORTED      , object.unblock_supported_    );
    object.attributeTable_.put( Attribute.TO_RESET_PIN_SUPPORTED    , object.reset_pin_supported_  );
    object.attributeTable_.put( Attribute.TO_CC                     , object.cc_                   );
    object.attributeTable_.put( Attribute.TO_DERIVE_UNBLOCK_FROM_SO , object.derive_unblock_from_so_);
    object.attributeTable_.put( Attribute.TO_MINIDRIVER_COMPATIBLE  , object.minidriver_compatible_);

    object.attributeTable_.put( Attribute.TO_FW_REVISION            , object.fw_revision_            );
    object.attributeTable_.put( Attribute.TO_CASE_MODEL             , object.case_model_             );
    object.attributeTable_.put( Attribute.TO_TOKEN_ID               , object.token_id_               );
    object.attributeTable_.put( Attribute.TO_CARD_TYPE              , object.card_type_              );
    object.attributeTable_.put( Attribute.TO_COLOR                  , object.color_                  );
    object.attributeTable_.put( Attribute.TO_RETRY_USER             , object.retry_user_             );
    object.attributeTable_.put( Attribute.TO_RETRY_SO               , object.retry_so_               );
    object.attributeTable_.put( Attribute.TO_RETRY_USER_MAX         , object.retry_user_max_         );
    object.attributeTable_.put( Attribute.TO_RETRY_SO_MAX           , object.retry_so_max_           );
    object.attributeTable_.put( Attribute.TO_FIPS_LEVEL             , object.fips_level_             );
    object.attributeTable_.put( Attribute.TO_CARD_REVISION          , object.card_revision_          );
    object.attributeTable_.put( Attribute.TO_PIN_TIMEOUT            , object.pin_timeout_            );
    object.attributeTable_.put( Attribute.TO_PIN_TIMEOUT_MAX        , object.pin_timeout_max_        );
    object.attributeTable_.put( Attribute.TO_CRYPTO_LOCK_MODE       , object.crypto_lock_mode_       );
    object.attributeTable_.put( Attribute.TO_CRYPTO_LOCK_STATE      , object.crypto_lock_state_      );
    object.attributeTable_.put( Attribute.TO_RSA_AREA_SIZE          , object.rsa_area_size_          );
    object.attributeTable_.put( Attribute.TO_FORMAT_VERSION         , object.format_version_         );
    object.attributeTable_.put( Attribute.TO_IDENTRUS_PIN_AGE       , object.identrus_pin_age_       );
    object.attributeTable_.put( Attribute.TO_USER_PIN_AGE           , object.user_pin_age_           );
    object.attributeTable_.put( Attribute.TO_USER_PIN_ITER          , object.user_pin_iter_          );
    object.attributeTable_.put( Attribute.TO_CARDMODULE_AREA_SIZE   , object.cardmodule_area_size_   );
    object.attributeTable_.put( Attribute.TO_RESERVED_RSA_KEYS_1024 , object.reserved_rsa_keys_1024_ );
    object.attributeTable_.put( Attribute.TO_RESERVED_RSA_KEYS_2048 , object.reserved_rsa_keys_2048_ );
    object.attributeTable_.put( Attribute.TO_FREE_MEMORY            , object.free_memory_            );
    object.attributeTable_.put( Attribute.TO_UNLOCK_COUNT           , object.unlock_count_           );
    object.attributeTable_.put( Attribute.TO_UNLOCK_MAX             , object.unlock_max_             );

    object.attributeTable_.put( Attribute.TO_PRODUCT_NAME    , object.product_name_    );
    object.attributeTable_.put( Attribute.TO_MODEL           , object.model_           );
    object.attributeTable_.put( Attribute.TO_PRODUCTION_DATE , object.production_date_ );
    object.attributeTable_.put( Attribute.TO_CC_CERTIFIED    , object.cc_certified_    );

    object.attributeTable_.put( Attribute.TO_HW_INTERNAL        , object.hw_internal_        );
    object.attributeTable_.put( Attribute.TO_CARD_ID            , object.card_id_            );
    object.attributeTable_.put( Attribute.TO_CARD_VERSION       , object.card_version_       );
    object.attributeTable_.put( Attribute.TO_INIT_PKI_VERSION   , object.init_pki_version_   );
    object.attributeTable_.put( Attribute.TO_CLIENTLESS_VERSION , object.clientless_version_ );
    object.attributeTable_.put( Attribute.TO_OS_RELEASE_VERSION , object.os_release_version_ );
    object.attributeTable_.put( Attribute.TO_HASHVAL            , object.hashval_            );
    object.attributeTable_.put( Attribute.TO_OS_NAME            , object.os_name_            );
    object.attributeTable_.put( Attribute.TO_PUK                , object.puk_                );
    object.attributeTable_.put( Attribute.TO_IMPORT_PIN         , object.import_pin_         );
  }
  
  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   *
   * @preconditions
   * @postconditions
   */
  protected void allocateAttributes() {
 
	super.allocateAttributes();

	label_ = new CharArrayAttribute(Attribute.LABEL);
	
	has_lcd_                 = new BooleanAttribute( Attribute.TO_HAS_LCD                );
	has_so_                  = new BooleanAttribute( Attribute.TO_HAS_SO                 );
	fips_                    = new BooleanAttribute( Attribute.TO_FIPS                   );
	init_pin_req_            = new BooleanAttribute( Attribute.TO_INIT_PIN_REQ           );
	rsa_2048_                = new BooleanAttribute( Attribute.TO_RSA_2048               );
	rsa_2048_supported_      = new BooleanAttribute( Attribute.TO_RSA_2048_SUPPORTED     );
	hmac_sha1_               = new BooleanAttribute( Attribute.TO_HMAC_SHA1              );
	hmac_sha1_supported_     = new BooleanAttribute( Attribute.TO_HMAC_SHA1_SUPPORTED    );
	real_color_              = new BooleanAttribute( Attribute.TO_REAL_COLOR             );
	may_init_                = new BooleanAttribute( Attribute.TO_MAY_INIT               );
	mass_storage_present_    = new BooleanAttribute( Attribute.TO_MASS_STORAGE_PRESENT   );
	mass_storage_secured_    = new BooleanAttribute( Attribute.TO_MASS_STORAGE_SECURED   );
	etoken_drive_            = new BooleanAttribute( Attribute.TO_ETOKEN_DRIVE           );
	one_factor_              = new BooleanAttribute( Attribute.TO_ONE_FACTOR             );
	etv_temporary_           = new BooleanAttribute( Attribute.TO_ETV_TEMPORARY          );
	fips_supported_          = new BooleanAttribute( Attribute.TO_FIPS_SUPPORTED         );
	override_retry_max_      = new BooleanAttribute( Attribute.TO_OVERRIDE_RETRY_MAX     );
	is_identrus_             = new BooleanAttribute( Attribute.TO_IS_IDENTRUS            );
	unblock_supported_       = new BooleanAttribute( Attribute.TO_UNBLOCK_SUPPORTED      );
	reset_pin_supported_     = new BooleanAttribute( Attribute.TO_RESET_PIN_SUPPORTED    );
	cc_                      = new BooleanAttribute( Attribute.TO_CC                     );
	derive_unblock_from_so_  = new BooleanAttribute( Attribute.TO_DERIVE_UNBLOCK_FROM_SO );
	minidriver_compatible_   = new BooleanAttribute( Attribute.TO_MINIDRIVER_COMPATIBLE  );

	fw_revision_            = new LongAttribute( Attribute.TO_FW_REVISION            );
	case_model_             = new LongAttribute( Attribute.TO_CASE_MODEL             );
	token_id_               = new LongAttribute( Attribute.TO_TOKEN_ID               );
	card_type_              = new LongAttribute( Attribute.TO_CARD_TYPE              );
	color_                  = new LongAttribute( Attribute.TO_COLOR                  );
	retry_user_             = new LongAttribute( Attribute.TO_RETRY_USER             );
	retry_so_               = new LongAttribute( Attribute.TO_RETRY_SO               );
	retry_user_max_         = new LongAttribute( Attribute.TO_RETRY_USER_MAX         );
	retry_so_max_           = new LongAttribute( Attribute.TO_RETRY_SO_MAX           );
	fips_level_             = new LongAttribute( Attribute.TO_FIPS_LEVEL             );
	card_revision_          = new LongAttribute( Attribute.TO_CARD_REVISION          );
	pin_timeout_            = new LongAttribute( Attribute.TO_PIN_TIMEOUT            );
	pin_timeout_max_        = new LongAttribute( Attribute.TO_PIN_TIMEOUT_MAX        );
	crypto_lock_mode_       = new LongAttribute( Attribute.TO_CRYPTO_LOCK_MODE       );
	crypto_lock_state_      = new LongAttribute( Attribute.TO_CRYPTO_LOCK_STATE      );
	rsa_area_size_          = new LongAttribute( Attribute.TO_RSA_AREA_SIZE          );
	format_version_         = new LongAttribute( Attribute.TO_FORMAT_VERSION         );
	identrus_pin_age_       = new LongAttribute( Attribute.TO_IDENTRUS_PIN_AGE       );
	user_pin_age_           = new LongAttribute( Attribute.TO_USER_PIN_AGE           );
	user_pin_iter_          = new LongAttribute( Attribute.TO_USER_PIN_ITER          );
	cardmodule_area_size_   = new LongAttribute( Attribute.TO_CARDMODULE_AREA_SIZE   );
	reserved_rsa_keys_1024_ = new LongAttribute( Attribute.TO_RESERVED_RSA_KEYS_1024 );
	reserved_rsa_keys_2048_ = new LongAttribute( Attribute.TO_RESERVED_RSA_KEYS_2048 );
	free_memory_            = new LongAttribute( Attribute.TO_FREE_MEMORY            );
	unlock_count_           = new LongAttribute( Attribute.TO_UNLOCK_COUNT           );
	unlock_max_             = new LongAttribute( Attribute.TO_UNLOCK_MAX             );

	product_name_     = new CharArrayAttribute( Attribute.TO_PRODUCT_NAME    );
	model_            = new CharArrayAttribute( Attribute.TO_MODEL           );
	production_date_  = new CharArrayAttribute( Attribute.TO_PRODUCTION_DATE );
	cc_certified_     = new CharArrayAttribute( Attribute.TO_CC_CERTIFIED    );

	hw_internal_         = new ByteArrayAttribute( Attribute.TO_HW_INTERNAL        );
	card_id_             = new ByteArrayAttribute( Attribute.TO_CARD_ID            );
	card_version_        = new ByteArrayAttribute( Attribute.TO_CARD_VERSION       );
	init_pki_version_    = new ByteArrayAttribute( Attribute.TO_INIT_PKI_VERSION   );
	clientless_version_  = new ByteArrayAttribute( Attribute.TO_CLIENTLESS_VERSION );
	os_release_version_  = new ByteArrayAttribute( Attribute.TO_OS_RELEASE_VERSION );
	hashval_             = new ByteArrayAttribute( Attribute.TO_HASHVAL            );
	os_name_             = new ByteArrayAttribute( Attribute.TO_OS_NAME            );
	puk_                 = new ByteArrayAttribute( Attribute.TO_PUK                );
	import_pin_          = new ByteArrayAttribute( Attribute.TO_IMPORT_PIN         );
	
    putAttributesInTable(this);
  }
  
  /**
   * Create a (deep) clone of this object.
   *
   * @return A clone of this object.
   * @preconditions
   * @postconditions (result <> null)
   *                 and (result instanceof pq)
   *                 and (result.equals(this))
   */
  public java.lang.Object clone() 
  {
	  TokenObject clone = (TokenObject) super.clone();

	  clone.label_ = (CharArrayAttribute) this.label_.clone();
	  
	  clone.has_lcd_               = (BooleanAttribute)this.has_lcd_               .clone();
	  clone.has_so_                = (BooleanAttribute)this.has_so_                .clone();
	  clone.fips_                  = (BooleanAttribute)this.fips_                  .clone();
	  clone.init_pin_req_          = (BooleanAttribute)this.init_pin_req_          .clone();
	  clone.rsa_2048_              = (BooleanAttribute)this.rsa_2048_              .clone();
	  clone.rsa_2048_supported_    = (BooleanAttribute)this.rsa_2048_supported_    .clone();
	  clone.hmac_sha1_             = (BooleanAttribute)this.hmac_sha1_             .clone();
	  clone.hmac_sha1_supported_   = (BooleanAttribute)this.hmac_sha1_supported_   .clone();
	  clone.real_color_            = (BooleanAttribute)this.real_color_            .clone();
	  clone.may_init_              = (BooleanAttribute)this.may_init_              .clone();
	  clone.mass_storage_present_  = (BooleanAttribute)this.mass_storage_present_  .clone();
	  clone.mass_storage_secured_  = (BooleanAttribute)this.mass_storage_secured_  .clone();
	  clone.etoken_drive_          = (BooleanAttribute)this.etoken_drive_          .clone();
	  clone.one_factor_            = (BooleanAttribute)this.one_factor_            .clone();
	  clone.etv_temporary_         = (BooleanAttribute)this.etv_temporary_         .clone();
	  clone.fips_supported_        = (BooleanAttribute)this.fips_supported_        .clone();
	  clone.override_retry_max_    = (BooleanAttribute)this.override_retry_max_    .clone();
	  clone.is_identrus_           = (BooleanAttribute)this.is_identrus_           .clone();
	  clone.unblock_supported_     = (BooleanAttribute)this.unblock_supported_     .clone();
	  clone.reset_pin_supported_   = (BooleanAttribute)this.reset_pin_supported_   .clone();
	  clone.cc_                    = (BooleanAttribute)this.cc_                    .clone();
	  clone.derive_unblock_from_so_= (BooleanAttribute)this.derive_unblock_from_so_.clone();
	  clone.minidriver_compatible_ = (BooleanAttribute)this.minidriver_compatible_ .clone();
	
	  clone.fw_revision_             = (LongAttribute)this.fw_revision_            .clone();
	  clone.case_model_              = (LongAttribute)this.case_model_             .clone();
	  clone.token_id_                = (LongAttribute)this.token_id_               .clone();
	  clone.card_type_               = (LongAttribute)this.card_type_              .clone();
	  clone.color_                   = (LongAttribute)this.color_                  .clone();
	  clone.retry_user_              = (LongAttribute)this.retry_user_             .clone();
	  clone.retry_so_                = (LongAttribute)this.retry_so_               .clone();
	  clone.retry_user_max_          = (LongAttribute)this.retry_user_max_         .clone();
	  clone.retry_so_max_            = (LongAttribute)this.retry_so_max_           .clone();
	  clone.fips_level_              = (LongAttribute)this.fips_level_             .clone();
	  clone.card_revision_           = (LongAttribute)this.card_revision_          .clone();
	  clone.pin_timeout_             = (LongAttribute)this.pin_timeout_            .clone();
	  clone.pin_timeout_max_         = (LongAttribute)this.pin_timeout_max_        .clone();
	  clone.crypto_lock_mode_        = (LongAttribute)this.crypto_lock_mode_       .clone();
	  clone.crypto_lock_state_       = (LongAttribute)this.crypto_lock_state_      .clone();
	  clone.rsa_area_size_           = (LongAttribute)this.rsa_area_size_          .clone();
	  clone.format_version_          = (LongAttribute)this.format_version_         .clone();
	  clone.identrus_pin_age_        = (LongAttribute)this.identrus_pin_age_       .clone();
	  clone.user_pin_age_            = (LongAttribute)this.user_pin_age_           .clone();
	  clone.user_pin_iter_           = (LongAttribute)this.user_pin_iter_          .clone();
	  clone.cardmodule_area_size_    = (LongAttribute)this.cardmodule_area_size_   .clone();
	  clone.reserved_rsa_keys_1024_  = (LongAttribute)this.reserved_rsa_keys_1024_ .clone();
	  clone.reserved_rsa_keys_2048_  = (LongAttribute)this.reserved_rsa_keys_2048_ .clone();
	  clone.free_memory_             = (LongAttribute)this.free_memory_            .clone();
	  clone.unlock_count_            = (LongAttribute)this.unlock_count_           .clone();
	  clone.unlock_max_              = (LongAttribute)this.unlock_max_             .clone();
	
	  clone.hw_internal_        = (ByteArrayAttribute)this.hw_internal_       .clone();
	  clone.card_id_            = (ByteArrayAttribute)this.card_id_           .clone();
	  clone.card_version_       = (ByteArrayAttribute)this.card_version_      .clone();
	  clone.init_pki_version_   = (ByteArrayAttribute)this.init_pki_version_  .clone();
	  clone.clientless_version_ = (ByteArrayAttribute)this.clientless_version_.clone();
	  clone.os_release_version_ = (ByteArrayAttribute)this.os_release_version_.clone();
	  clone.hashval_            = (ByteArrayAttribute)this.hashval_           .clone();
	  clone.os_name_            = (ByteArrayAttribute)this.os_name_           .clone();
	  clone.puk_                = (ByteArrayAttribute)this.puk_               .clone();
	  clone.import_pin_         = (ByteArrayAttribute)this.import_pin_        .clone();
	
	  clone.product_name_    = (CharArrayAttribute)this.product_name_   .clone();
	  clone.model_           = (CharArrayAttribute)this.model_          .clone();
	  clone.production_date_ = (CharArrayAttribute)this.production_date_.clone();
	  clone.cc_certified_    = (CharArrayAttribute)this.cc_certified_   .clone();

	  putAttributesInTable(clone); // put all cloned attributes into the new table

	  return clone ;
  }
  
  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject The other object to compare to.
   * @return True, if other is an instance of Info and all member variables of
   *         both objects are equal. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof TokenObject) {
      TokenObject other = (TokenObject) otherObject;
      equal = (this == other) ||
              (
                super.equals(other)
                && this.label_.equals(other.label_)
                && this.has_lcd_               .equals(other.has_lcd_               )
                && this.has_so_                .equals(other.has_so_                )
                && this.fips_                  .equals(other.fips_                  )
                && this.init_pin_req_          .equals(other.init_pin_req_          )
                && this.rsa_2048_              .equals(other.rsa_2048_              )
                && this.rsa_2048_supported_    .equals(other.rsa_2048_supported_    )
                && this.hmac_sha1_             .equals(other.hmac_sha1_             )
                && this.hmac_sha1_supported_   .equals(other.hmac_sha1_supported_   )
                && this.real_color_            .equals(other.real_color_            )
                && this.may_init_              .equals(other.may_init_              )
                && this.mass_storage_present_  .equals(other.mass_storage_present_  )
                && this.mass_storage_secured_  .equals(other.mass_storage_secured_  )
                && this.etoken_drive_          .equals(other.etoken_drive_          )
                && this.one_factor_            .equals(other.one_factor_            )
                && this.etv_temporary_         .equals(other.etv_temporary_         )
                && this.fips_supported_        .equals(other.fips_supported_        )
                && this.override_retry_max_    .equals(other.override_retry_max_    )
                && this.is_identrus_           .equals(other.is_identrus_           )
                && this.unblock_supported_     .equals(other.unblock_supported_     )
                && this.reset_pin_supported_   .equals(other.reset_pin_supported_   )
                && this.cc_                    .equals(other.cc_                    )
                && this.derive_unblock_from_so_.equals(other.derive_unblock_from_so_)
                && this.minidriver_compatible_ .equals(other.minidriver_compatible_ )
                && this.fw_revision_           .equals(other.fw_revision_           )
                && this.case_model_            .equals(other.case_model_            )
                && this.token_id_              .equals(other.token_id_              )
                && this.card_type_             .equals(other.card_type_             )
                && this.color_                 .equals(other.color_                 )
                && this.retry_user_            .equals(other.retry_user_            )
                && this.retry_so_              .equals(other.retry_so_              )
                && this.retry_user_max_        .equals(other.retry_user_max_        )
                && this.retry_so_max_          .equals(other.retry_so_max_          )
                && this.fips_level_            .equals(other.fips_level_            )
                && this.card_revision_         .equals(other.card_revision_         )
                && this.pin_timeout_           .equals(other.pin_timeout_           )
                && this.pin_timeout_max_       .equals(other.pin_timeout_max_       )
                && this.crypto_lock_mode_      .equals(other.crypto_lock_mode_      )
                && this.crypto_lock_state_     .equals(other.crypto_lock_state_     )
                && this.rsa_area_size_         .equals(other.rsa_area_size_         )
                && this.format_version_        .equals(other.format_version_        )
                && this.identrus_pin_age_      .equals(other.identrus_pin_age_      )
                && this.user_pin_age_          .equals(other.user_pin_age_          )
                && this.user_pin_iter_         .equals(other.user_pin_iter_         )
                && this.cardmodule_area_size_  .equals(other.cardmodule_area_size_  )
                && this.reserved_rsa_keys_1024_.equals(other.reserved_rsa_keys_1024_)
                && this.reserved_rsa_keys_2048_.equals(other.reserved_rsa_keys_2048_)
                && this.free_memory_           .equals(other.free_memory_           )
                && this.unlock_count_          .equals(other.unlock_count_          )
                && this.unlock_max_            .equals(other.unlock_max_            )
                && this.product_name_   .equals(other.product_name_   )
                && this.model_          .equals(other.model_          )
                && this.production_date_.equals(other.production_date_)
                && this.cc_certified_   .equals(other.cc_certified_   )
                && this.hw_internal_       .equals(other.hw_internal_       )
                && this.card_id_           .equals(other.card_id_           )
                && this.card_version_      .equals(other.card_version_      )
                && this.init_pki_version_  .equals(other.init_pki_version_  )
                && this.clientless_version_.equals(other.clientless_version_)
                && this.os_release_version_.equals(other.os_release_version_)
                && this.hashval_           .equals(other.hashval_           )
                && this.os_name_           .equals(other.os_name_           )
                //&& this.puk_       .equals(other.puk_               )
                //&& this.import_pin_.equals(other.import_pin_        )
              );
    }

    return equal ;
  }

  /**
   * Get the label attribute of this object.
   *
   * @return Contains the label as a char array.
   * @preconditions
   * @postconditions (result <> null)
   */
  public CharArrayAttribute getLabel() {
    return label_ ;
  }
  
  public BooleanAttribute getHasLcd               () {  return has_lcd_;                }
  public BooleanAttribute getHasSO                () {  return has_so_;                 }
  public BooleanAttribute getFips                 () {  return fips_;                   }
  public BooleanAttribute getInitPinReq           () {  return init_pin_req_;           }
  public BooleanAttribute getRsa2048              () {  return rsa_2048_;               }
  public BooleanAttribute getRsa2048Supported     () {  return rsa_2048_supported_;     }
  public BooleanAttribute getHmacSha1             () {  return hmac_sha1_;              }
  public BooleanAttribute getHmacSha1Supported    () {  return hmac_sha1_supported_;    }
  public BooleanAttribute getRealColor            () {  return real_color_;             }
  public BooleanAttribute getMayInit              () {  return may_init_;               }
  public BooleanAttribute getMassStoragePresent   () {  return mass_storage_present_;   }
  public BooleanAttribute getMassStorageSecured   () {  return mass_storage_secured_;   }
  public BooleanAttribute getEtokenDrive          () {  return etoken_drive_;           }
  public BooleanAttribute getOneFactor            () {  return one_factor_;             }
  public BooleanAttribute getEtvTemporary         () {  return etv_temporary_;          }
  public BooleanAttribute getFipsSupported        () {  return fips_supported_;         }
  public BooleanAttribute getOverrideRetryMax     () {  return override_retry_max_;     }
  public BooleanAttribute getIsIdentrus           () {  return is_identrus_;            }
  public BooleanAttribute getUnblockSupported     () {  return unblock_supported_;      }
  public BooleanAttribute getResetPinSupported    () {  return reset_pin_supported_;    }
  public BooleanAttribute getCC                   () {  return cc_;                     }
  public BooleanAttribute getDeriveUnblockFromSO  () {  return derive_unblock_from_so_; }
  public BooleanAttribute getMiniDriverCompatible () {  return minidriver_compatible_;  }

  public LongAttribute getFwRevision          () {  return fw_revision_;            }
  public LongAttribute getCaseModel           () {  return case_model_;             }
  public LongAttribute getTokenId             () {  return token_id_;               }
  public LongAttribute getCardType            () {  return card_type_;              }
  public LongAttribute getColor               () {  return color_;                  }
  public LongAttribute getRetryUser           () {  return retry_user_;             }
  public LongAttribute getRetrySO             () {  return retry_so_;               }
  public LongAttribute getRetryUserMax        () {  return retry_user_max_;         }
  public LongAttribute getRetrySOMax          () {  return retry_so_max_;           }
  public LongAttribute getFipsLevel           () {  return fips_level_;             }
  public LongAttribute getCardRevision        () {  return card_revision_;          }
  public LongAttribute getPinTimeout          () {  return pin_timeout_;            }
  public LongAttribute getPinTimeoutMax       () {  return pin_timeout_max_;        }
  public LongAttribute getCryptoLockMode      () {  return crypto_lock_mode_;       }
  public LongAttribute getCryptoLockState     () {  return crypto_lock_state_;      }
  public LongAttribute getRsaAreaSize         () {  return rsa_area_size_;          }
  public LongAttribute getFormatVersion       () {  return format_version_;         }
  public LongAttribute getIdentrusPinAge      () {  return identrus_pin_age_;       }
  public LongAttribute getUserPinAge          () {  return user_pin_age_;           }
  public LongAttribute getUserPinIter         () {  return user_pin_iter_;          }
  public LongAttribute getCardmoduleAreaSize  () {  return cardmodule_area_size_;   }
  public LongAttribute getReservedRsaKeys1024 () {  return reserved_rsa_keys_1024_; }
  public LongAttribute getReservedRsaKeys2048 () {  return reserved_rsa_keys_2048_; }
  public LongAttribute getFreeMemory          () {  return free_memory_;            }
  public LongAttribute getUnlockCount         () {  return unlock_count_;           }
  public LongAttribute getUnlockMax           () {  return unlock_max_;             }
  
  public CharArrayAttribute getProduct_name  () {  return product_name_;    }
  public CharArrayAttribute getModel         () {  return model_;           }
  public CharArrayAttribute getProductionDate() {  return production_date_; }
  public CharArrayAttribute getCcCertified   () {  return cc_certified_;    }

  public ByteArrayAttribute getHwInternal       () {  return hw_internal_;        }
  public ByteArrayAttribute getCardId           () {  return card_id_;            }
  public ByteArrayAttribute getCardVersion      () {  return card_version_;       }
  public ByteArrayAttribute getInitPkiVersion   () {  return init_pki_version_;   }
  public ByteArrayAttribute getClientlessVersion() {  return clientless_version_; }
  public ByteArrayAttribute getOsReleaseVersion () {  return os_release_version_; }
  public ByteArrayAttribute getHashVal          () {  return hashval_;            }
  public ByteArrayAttribute getOsName           () {  return os_name_;            }
  //public ByteArrayAttribute getPuk            () {  return puk_;                }
  //public ByteArrayAttribute getImportPin      () {  return import_pin_;         }

  /**
   * The overriding of this method should ensure that the objects of this class
   * work correctly in a hashtable.
   *
   * @return The hash code of this object.
   * @preconditions
   * @postconditions
   */
  public int hashCode() {
    return  label_.hashCode()
    	  ^ has_lcd_               .hashCode()
          ^ has_so_                .hashCode()
          ^ fips_                  .hashCode()
          ^ init_pin_req_          .hashCode()
          ^ rsa_2048_              .hashCode()
          ^ rsa_2048_supported_    .hashCode()
          ^ hmac_sha1_             .hashCode()
          ^ hmac_sha1_supported_   .hashCode()
          ^ real_color_            .hashCode()
          ^ may_init_              .hashCode()
          ^ mass_storage_present_  .hashCode()
          ^ mass_storage_secured_  .hashCode()
          ^ etoken_drive_          .hashCode()
          ^ one_factor_            .hashCode()
          ^ etv_temporary_         .hashCode()
          ^ fips_supported_        .hashCode()
          ^ override_retry_max_    .hashCode()
          ^ is_identrus_           .hashCode()
          ^ unblock_supported_     .hashCode()
          ^ reset_pin_supported_   .hashCode()
          ^ cc_                    .hashCode()
          ^ derive_unblock_from_so_.hashCode()
          ^ minidriver_compatible_ .hashCode()
          ^ fw_revision_           .hashCode()
          ^ case_model_            .hashCode()
          ^ token_id_              .hashCode()
          ^ card_type_             .hashCode()
          ^ color_                 .hashCode()
          ^ retry_user_            .hashCode()
          ^ retry_so_              .hashCode()
          ^ retry_user_max_        .hashCode()
          ^ retry_so_max_          .hashCode()
          ^ fips_level_            .hashCode()
          ^ card_revision_         .hashCode()
          ^ pin_timeout_           .hashCode()
          ^ pin_timeout_max_       .hashCode()
          ^ crypto_lock_mode_      .hashCode()
          ^ crypto_lock_state_     .hashCode()
          ^ rsa_area_size_         .hashCode()
          ^ format_version_        .hashCode()
          ^ identrus_pin_age_      .hashCode()
          ^ user_pin_age_          .hashCode()
          ^ user_pin_iter_         .hashCode()
          ^ cardmodule_area_size_  .hashCode()
          ^ reserved_rsa_keys_1024_.hashCode()
          ^ reserved_rsa_keys_2048_.hashCode()
          ^ free_memory_           .hashCode()
          ^ unlock_count_          .hashCode()
          ^ unlock_max_            .hashCode()
          ^ product_name_          .hashCode()
          ^ model_                 .hashCode()
          ^ production_date_       .hashCode()
          ^ cc_certified_          .hashCode()
          ^ hw_internal_           .hashCode()
          ^ card_id_               .hashCode()
          ^ card_version_          .hashCode()
          ^ init_pki_version_      .hashCode()
          ^ clientless_version_    .hashCode()
          ^ os_release_version_    .hashCode()
          ^ hashval_               .hashCode()
          ^ os_name_               .hashCode();
  }

  /**
   * Read the values of the attributes of this object from the token.
   *
   * @param session The session handle to use for reading attributes.
   *                This session must have the appropriate rights; i.e.
   *                it must be a user-session, if it is a private object.
   * @exception TokenException If getting the attributes failed.
   * @preconditions (session <> null)
   * @postconditions
   */
  public void readAttributes(Session session)
      throws TokenException
  {
    super.readAttributes(session);

    Object.getAttributeValue(session, objectHandle_, label_);
    
    Object.getAttributeValue( session, objectHandle_, has_lcd_                );
    Object.getAttributeValue( session, objectHandle_, has_so_                 );
    Object.getAttributeValue( session, objectHandle_, fips_                   );
    Object.getAttributeValue( session, objectHandle_, init_pin_req_           );
    Object.getAttributeValue( session, objectHandle_, rsa_2048_               );
    Object.getAttributeValue( session, objectHandle_, rsa_2048_supported_     );
    Object.getAttributeValue( session, objectHandle_, hmac_sha1_              );
    Object.getAttributeValue( session, objectHandle_, hmac_sha1_supported_    );
    Object.getAttributeValue( session, objectHandle_, real_color_             );
    Object.getAttributeValue( session, objectHandle_, may_init_               );
    Object.getAttributeValue( session, objectHandle_, mass_storage_present_   );
    Object.getAttributeValue( session, objectHandle_, mass_storage_secured_   );
    Object.getAttributeValue( session, objectHandle_, etoken_drive_           );
    Object.getAttributeValue( session, objectHandle_, one_factor_             );
    Object.getAttributeValue( session, objectHandle_, etv_temporary_          );
    Object.getAttributeValue( session, objectHandle_, fips_supported_         );
    Object.getAttributeValue( session, objectHandle_, override_retry_max_     );
    Object.getAttributeValue( session, objectHandle_, is_identrus_            );
    Object.getAttributeValue( session, objectHandle_, unblock_supported_      );
    Object.getAttributeValue( session, objectHandle_, reset_pin_supported_    );
    Object.getAttributeValue( session, objectHandle_, cc_                     );
    Object.getAttributeValue( session, objectHandle_, derive_unblock_from_so_ );
    Object.getAttributeValue( session, objectHandle_, minidriver_compatible_  );
    Object.getAttributeValue( session, objectHandle_, fw_revision_            );
    Object.getAttributeValue( session, objectHandle_, case_model_             );
    Object.getAttributeValue( session, objectHandle_, token_id_               );
    Object.getAttributeValue( session, objectHandle_, card_type_              );
    Object.getAttributeValue( session, objectHandle_, color_                  );
    Object.getAttributeValue( session, objectHandle_, retry_user_             );
    Object.getAttributeValue( session, objectHandle_, retry_so_               );
    Object.getAttributeValue( session, objectHandle_, retry_user_max_         );
    Object.getAttributeValue( session, objectHandle_, retry_so_max_           );
    Object.getAttributeValue( session, objectHandle_, fips_level_             );
    Object.getAttributeValue( session, objectHandle_, card_revision_          );
    Object.getAttributeValue( session, objectHandle_, pin_timeout_            );
    Object.getAttributeValue( session, objectHandle_, pin_timeout_max_        );
    Object.getAttributeValue( session, objectHandle_, crypto_lock_mode_       );
    Object.getAttributeValue( session, objectHandle_, crypto_lock_state_      );
    Object.getAttributeValue( session, objectHandle_, rsa_area_size_          );
    Object.getAttributeValue( session, objectHandle_, format_version_         );
    Object.getAttributeValue( session, objectHandle_, identrus_pin_age_       );
    Object.getAttributeValue( session, objectHandle_, user_pin_age_           );
    Object.getAttributeValue( session, objectHandle_, user_pin_iter_          );
    Object.getAttributeValue( session, objectHandle_, cardmodule_area_size_   );
    Object.getAttributeValue( session, objectHandle_, reserved_rsa_keys_1024_ );
    Object.getAttributeValue( session, objectHandle_, reserved_rsa_keys_2048_ );
    Object.getAttributeValue( session, objectHandle_, free_memory_            );
    Object.getAttributeValue( session, objectHandle_, unlock_count_           );
    Object.getAttributeValue( session, objectHandle_, unlock_max_             );
    Object.getAttributeValue( session, objectHandle_, product_name_           );
    Object.getAttributeValue( session, objectHandle_, model_                  );
    Object.getAttributeValue( session, objectHandle_, production_date_        );
    Object.getAttributeValue( session, objectHandle_, cc_certified_           );
    Object.getAttributeValue( session, objectHandle_, hw_internal_            );
    Object.getAttributeValue( session, objectHandle_, card_id_                );
    Object.getAttributeValue( session, objectHandle_, card_version_           );
    Object.getAttributeValue( session, objectHandle_, init_pki_version_       );
    Object.getAttributeValue( session, objectHandle_, clientless_version_     );
    Object.getAttributeValue( session, objectHandle_, os_release_version_     );
    Object.getAttributeValue( session, objectHandle_, hashval_                );
    Object.getAttributeValue( session, objectHandle_, os_name_                );
  }

  /**
   * This method returns a string representation of the current object. The
   * output is only for debugging purposes and should not be used for other
   * purposes.
   *
   * @return A string presentation of this object for debugging output.
   * @preconditions
   * @postconditions (result <> null)
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer(256);

    buffer.append(super.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Label: ");
    buffer.append(label_.toString());
    
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("has_lcd: "                );  buffer.append(has_lcd_.toString()               );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("has_so: "                 );  buffer.append(has_so_.toString()                );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("fips: "                   );  buffer.append(fips_.toString()                  );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("init_pin_req: "           );  buffer.append(init_pin_req_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("rsa_2048: "               );  buffer.append(rsa_2048_.toString()              );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("rsa_2048_supported: "     );  buffer.append(rsa_2048_supported_.toString()    );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("hmac_sha1: "              );  buffer.append(hmac_sha1_.toString()             );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("hmac_sha1_supported: "    );  buffer.append(hmac_sha1_supported_.toString()   );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("real_color: "             );  buffer.append(real_color_.toString()            );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("may_init: "               );  buffer.append(may_init_.toString()              );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("mass_storage_present: "   );  buffer.append(mass_storage_present_.toString()  );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("mass_storage_secured: "   );  buffer.append(mass_storage_secured_.toString()  );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("etoken_drive: "           );  buffer.append(etoken_drive_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("one_factor: "             );  buffer.append(one_factor_.toString()            );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("etv_temporary: "          );  buffer.append(etv_temporary_.toString()         );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("fips_supported: "         );  buffer.append(fips_supported_.toString()        );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("override_retry_max: "     );  buffer.append(override_retry_max_.toString()    );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("is_identrus: "            );  buffer.append(is_identrus_.toString()           );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("unblock_supported: "      );  buffer.append(unblock_supported_.toString()     );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("reset_pin_supported: "    );  buffer.append(reset_pin_supported_.toString()   );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("cc: "                     );  buffer.append(cc_.toString()                    );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("derive_unblock_from_so: " );  buffer.append(derive_unblock_from_so_.toString());
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("minidriver_compatible: "  );  buffer.append(minidriver_compatible_.toString() );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("fw_revision: "            );  buffer.append(fw_revision_.toString()           );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("case_model: "             );  buffer.append(case_model_.toString()            );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("token_id: "               );  buffer.append(token_id_.toString()              );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("card_type: "              );  buffer.append(card_type_.toString()             );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("color: "                  );  buffer.append(color_.toString()                 );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("retry_user: "             );  buffer.append(retry_user_.toString()            );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("retry_so: "               );  buffer.append(retry_so_.toString()              );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("retry_user_max: "         );  buffer.append(retry_user_max_.toString()        );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("retry_so_max: "           );  buffer.append(retry_so_max_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("fips_level: "             );  buffer.append(fips_level_.toString()            );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("card_revision: "          );  buffer.append(card_revision_.toString()         );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("pin_timeout: "            );  buffer.append(pin_timeout_.toString()           );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("pin_timeout_max: "        );  buffer.append(pin_timeout_max_.toString()       );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("crypto_lock_mode: "       );  buffer.append(crypto_lock_mode_.toString()      );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("crypto_lock_state: "      );  buffer.append(crypto_lock_state_.toString()     );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("rsa_area_size: "          );  buffer.append(rsa_area_size_.toString()         );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("format_version: "         );  buffer.append(format_version_.toString()        );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("identrus_pin_age: "       );  buffer.append(identrus_pin_age_.toString()      );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("user_pin_age: "           );  buffer.append(user_pin_age_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("user_pin_iter: "          );  buffer.append(user_pin_iter_.toString()         );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("cardmodule_area_size: "   );  buffer.append(cardmodule_area_size_.toString()  );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("reserved_rsa_keys_1024: " );  buffer.append(reserved_rsa_keys_1024_.toString());
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("reserved_rsa_keys_2048: " );  buffer.append(reserved_rsa_keys_2048_.toString());
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("free_memory: "            );  buffer.append(free_memory_.toString()           );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("unlock_count: "           );  buffer.append(unlock_count_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("unlock_max: "             );  buffer.append(unlock_max_.toString()            );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("product_name: "           );  buffer.append(product_name_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("model: "                  );  buffer.append(model_.toString()                 );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("production_date: "        );  buffer.append(production_date_.toString()       );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("cc_certified: "           );  buffer.append(cc_certified_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("hw_internal: "            );  buffer.append(hw_internal_.toString()           );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("card_id: "                );  buffer.append(card_id_.toString()               );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("card_version: "           );  buffer.append(card_version_.toString()          );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("init_pki_version: "       );  buffer.append(init_pki_version_.toString()      );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("clientless_version: "     );  buffer.append(clientless_version_.toString()    );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("os_release_version: "     );  buffer.append(os_release_version_.toString()    );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("hashval: "                );  buffer.append(hashval_.toString()               );
    buffer.append(Constants.NEWLINE); buffer.append(Constants.INDENT); buffer.append("os_name: "                );  buffer.append(os_name_.toString()               );
    
    return buffer.toString() ;
  }
}
