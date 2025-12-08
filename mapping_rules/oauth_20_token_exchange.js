importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.oauth20);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importPackage(Packages.com.tivoli.am.fim.fedmgr2.trust.util);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

/**
 * This function doTokenExchangePre shows an example of validate token claims and generate the access_token for 
 * the oauth 2.0 token exhcange.
 * 
 * This is an example of how you could to validate the subject token and actor token claims 
 * before the access token is generated, therefore preventing the scenario where request token 
 * claims are invalid and then you could choose to generate the access_token in this script or 
 * generate in the default module.
 */


/**
 * @param: useSTSforTokenGenerate - Config option to generate the token from this pre mapping rule.
 * IVIA will issue a regular access token if the varialbe set to false.
 * If set to true, STS chain will be called to generate the token.
 *
 * @param: store_dbConfig - Config option to stored the token which generated through this mapping rule to DB. This should be set
 * to true if need to store the token into the oauth20_token_cache and set to flase if not.
 * This variable is ignored if not using the STS to generate the token.
 */
function doTokenExchangePre (useSTSforTokenGenerate, store_db) {
    /**
     * Discover the request_type and the grant type
     */
    var request_type = null;
    var grant_type = null;

    // The request type - if none available assume 'resource'
    var global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("request_type", "urn:ibm:names:ITFIM:oauth:request");
    if (global_temp_attr != null && global_temp_attr.length > 0) {
        request_type = global_temp_attr[0];
    } else {
        request_type = "resource";
    }

    // The grant type
    global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("grant_type", "urn:ibm:names:ITFIM:oauth:body:param");
    if (global_temp_attr != null && global_temp_attr.length > 0) {
        grant_type = global_temp_attr[0];
    }

    if (request_type == "access_token" && grant_type == "urn:ietf:params:oauth:grant-type:token-exchange") {

        var subject_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("subject_token", "urn:ibm:names:ITFIM:oauth:body:param");
        var subject_token_type = stsuu.getContextAttributes().getAttributeValueByNameAndType("subject_token_type", "urn:ibm:names:ITFIM:oauth:body:param");
        var actor_token = stsuu.getContextAttributes().getAttributeValueByNameAndType("actor_token", "urn:ibm:names:ITFIM:oauth:body:param");
        var actor_token_type = stsuu.getContextAttributes().getAttributeValueByNameAndType("actor_token_type", "urn:ibm:names:ITFIM:oauth:body:param");
        var requested_token_type = stsuu.getContextAttributes().getAttributeValueByNameAndType("requested_token_type", "urn:ibm:names:ITFIM:oauth:body:param");
        var target = stsuu.getContextAttributes().getAttributeValueByNameAndType("resource", "urn:ibm:names:ITFIM:oauth:body:param");
        if (target == null) {
            target = stsuu.getContextAttributes().getAttributeValueByNameAndType("audience", "urn:ibm:names:ITFIM:oauth:body:param");
        }
        
        stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("username", "urn:ibm:names:ITFIM:oauth:rule:decision", "username"));

        /**
         * Validate actor token first then pass it to the subject token validation below.
         * Reason is existing WS-Trust STS chains may use only one chain to validate and issue new token.
         * So in such scenario, we can just inject the actor context into the chain.
         */
        var actorClaims = null;

        // Delegation use-case, actor specified
        if (actor_token != null && actor_token_type != null) {
            /**
             * Validate 'actor_token' by calling STS chain
             */
            actorClaims = LocalSTSClient.doRequest("http://schemas.xmlsoap.org/ws/2005/02/trust/Validate",
                actor_token_type, // STS chain appliesTo is based on the 'actor_token_type'
                OAuthMappingExtUtils.extractIssuer(actor_token, actor_token_type), // STS chain issuer is based on 'actor_token' iss claim
                OAuthMappingExtUtils.createTokenElement(actor_token, actor_token_type), // Insert the actor_token here
                null);

            if (actorClaims.errorMessage != null) {
                OAuthMappingExtUtils.throwSTSCustomUserPageException("The actor_token verification failed.", 400, "invalid_request");
            }
        }

        /**
         * Validate 'subject_token' by calling STS chain
         */
        var actClaimToken = null;
        if (actorClaims != null) {
            actClaimToken = actorClaims.token;
        }
        var subjectClaims = LocalSTSClient.doRequest("http://schemas.xmlsoap.org/ws/2005/02/trust/Validate",
            subject_token_type, // STS chain appliesTo is based on the 'subject_token_type'
            OAuthMappingExtUtils.extractIssuer(subject_token, subject_token_type), // STS chain issuer is based on 'subject_token' iss claim
            OAuthMappingExtUtils.createTokenElement(subject_token, subject_token_type), // Insert the subject_token here
            actClaimToken); // Inject the actor context into this chain

        if (subjectClaims.errorMessage != null) {
            OAuthMappingExtUtils.throwSTSCustomUserPageException("The subject_token verification failed.", 400, "invalid_request");
        }

        /**
         * Generate subject_token claims json and actor_token claims json with a universal name.
         * universalNameMapJson will record the original name and universal name mapping based on different token type.
         *
         * Supported token types are:
         * 1. urn:ietf:params:oauth:token-type:jwt
         */
        var universalNameMapJson = {
            "urn:ietf:params:oauth:token-type:jwt": {
                "sub": "uni_sub",
                "aud": "uni_aud",
                "exp": "uni_exp",
                "iss": "uni_iss",
                "scope": "uni_scope",
                "act": "uni_act"
            }
        };

        var act_stsuu = null;
        if (actorClaims != null) {
            act_stsuu = new STSUniversalUser(actorClaims.token);
        }
        
        var sub_stsuu = new STSUniversalUser(subjectClaims.token);

        var actClaimsJson = null;
        if (act_stsuu != null) {
            actClaimsJson = JSON.parse(
                OAuthMappingExtUtils.parseSTSUUToJson(act_stsuu, actor_token_type, JSON.stringify(universalNameMapJson))
            );
        }

        var subClaimsJson = JSON.parse(
            OAuthMappingExtUtils.parseSTSUUToJson(sub_stsuu, subject_token_type, JSON.stringify(universalNameMapJson))
        );

        if (actClaimsJson != null && actClaimsJson.uni_act) {
            stsuu.addContextAttribute(new Attribute("act", "urn:ibm:names:ITFIM:oauth:body:param", JSON.stringify(actClaimsJson.uni_act)));
        }
        
        if (useSTSforTokenGenerate) {
            /**
             * Choose to decide whether the new token should be issued.
             */
            if (target == '/finance' && subjectClaims.uni_sub == 'user@ibm.com') {
                OAuthMappingExtUtils.throwSTSUserMessageException("User is not authorized!");
            } else {

                /**
                 * Populating the claims in the new token
                 */
                var req_stsuu = new STSUniversalUser();
                if (subClaimsJson.uni_sub != null) {
                    req_stsuu.addAttribute(new Attribute("sub", "urn:ibm:jwt:claim", subClaimsJson.uni_sub));
                }
                if (actClaimsJson != null && actClaimsJson.uni_sub != null) {
                    req_stsuu.addAttribute(new Attribute("act", "urn:ibm:jwt:claim", actClaimsJson.uni_sub));
                }

                var base_element = req_stsuu.toXML().getDocumentElement();
                var rsp = LocalSTSClient.doRequest("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
                    requested_token_type, // STS chain appliesTo is based on the 'requested_token_type'
                    target, // STS chain issuer is based on the 'audience' or 'resource' requested
                    base_element, // Token claims
                    null);

                var jwtToken = IDMappingExtUtils.extractBinarySecurityToken(rsp.token);
                if (jwtToken != null) {

                    if (store_db) {
                        /**
                         * Store the generated token into the stsuu and the token will be stored to DB when default module is called.
                         * Whether the token need to be stored persistent need to be indicated in the STSUU.
                         */
                        stsuu.addContextAttribute(new Attribute("urn:ibm:ITFIM:oauth20:custom:token:access_token", "urn:ibm:ITFIM:oauth20:custom:token", jwtToken));
                        stsuu.addContextAttribute(new Attribute("urn:ibm:ITFIM:oauth20:custom:token:access_token", "urn:ibm:ITFIM:oauth20:custom:token:persistent", "false"));
                        stsuu.addContextAttribute(new Attribute("issued_token_type", "urn:ibm:names:ITFIM:oauth:response:attribute", requested_token_type));
                    } else {
                        /**
                         * Start populating the output
                         */
                        stsuu.addContextAttribute(new Attribute("access_token", "urn:ibm:names:ITFIM:oauth:response:attribute", jwtToken));
                        stsuu.addContextAttribute(new Attribute("issued_token_type", "urn:ibm:names:ITFIM:oauth:response:attribute", requested_token_type));
                        stsuu.addContextAttribute(new Attribute("token_type", "urn:ibm:names:ITFIM:oauth:response:attribute", "Bearer"));
                        stsuu.addContextAttribute(new Attribute("expires_in", "urn:ibm:names:ITFIM:oauth:response:attribute", "3600"));
                    }
                }
            }
        }
    }
}



/**
 * This function doTokenExchangePost() contains scenarios which occur post oauth 2.0 token exchange creation. This
 * includes examples for:
 *
 * 1. Store the "act" claims in the actor_token into the OAuth Token extra attributes table.
 *    
 *    The sub value of the "act" claims will be saved as the attribute value and "act:0" as the attribute name
 *    associate with the state id.
 *    If nested "act" claims exist. All sub value will be saved to attribute balue and the attribute name will 
 *    be stored as "act:{nested level}", associate with the same state id.
 *    
 *    For example, the "act" claims is:
 *    {
 *      "act": {
 *        "sub": "https://service16.example.com",
 *        "act": {
 *        "sub": "https://service77.example.com"
 *        }
 *      }
 *    }   
 *   
 *    The oauth20_token_extra_attribute will be stored as:
 *    state_id | attr_name | attr_value 
 *    id         act:0       https://service16.example.com
 *    id         act:1       https://service77.example.com 
 */

 function doTokenExchangePost() {
	/**
	 * Discover the request_type and the grant type
	 */
	var request_type = null;
	var grant_type = null;
	var state_id = null;

	// The request type - if none available assume 'resource'
	var global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("request_type", "urn:ibm:names:ITFIM:oauth:request");
	if (global_temp_attr != null && global_temp_attr.length > 0) {
		request_type = global_temp_attr[0];
	} else {
		request_type = "resource";
	}

	// The grant type
	global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("grant_type", "urn:ibm:names:ITFIM:oauth:body:param");
	if (global_temp_attr != null && global_temp_attr.length > 0) {
		grant_type = global_temp_attr[0];
	}

	// The state id handle
	global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("state_id", "urn:ibm:names:ITFIM:oauth:state");
	if (global_temp_attr != null && global_temp_attr.length > 0) {
		state_id = global_temp_attr[0];
	}

	IDMappingExtUtils.traceString("request_type: " + request_type);
	IDMappingExtUtils.traceString("state_id: " + state_id);

	if (request_type == "access_token" && grant_type == "urn:ietf:params:oauth:grant-type:token-exchange") {
		var act_claims = null;
		var act_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("act", "urn:ibm:names:ITFIM:oauth:body:param");
		if (act_temp_attr != null && act_temp_attr.length > 0) {
			act_claims = act_temp_attr[0];
		}
		
		if (act_claims != null && state_id != null) {
			OAuthMappingExtUtils.storeJwtActor(act_claims, state_id);
		}
	}
}
