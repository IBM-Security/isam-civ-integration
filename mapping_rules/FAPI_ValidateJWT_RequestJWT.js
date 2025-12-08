importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.oauth20);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);

var claims_str = stsuu.getContextAttributes().getAttributeValueByNameAndType("claim_json", "urn:com:ibm:JWT");
var claims = JSON.parse(claims_str);
var header_str = stsuu.getContextAttributes().getAttributeValueByNameAndType("header", "urn:com:ibm:JWT");
var headers = JSON.parse(header_str);
var defID = OAuthMappingExtUtils.getClient(claims.iss).getDefinitionID();

if(defID != null && OAuthMappingExtUtils.getDefinitionByID(defID).getOidc() != null & OAuthMappingExtUtils.getDefinitionByID(defID).getOidc().getFapiCompliant()){
	/* 
	 * Checks that request object contains exp, scope, nonce, redirect_uri.
	 */
	requestObjPass = true
	if ( claims.exp == undefined){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("exp is missing in request object.",400,"invalid_request");
	}
        if ( claims.nbf == undefined){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("nbf is missing in request object.",400,"invalid_request");
	}
	if ( claims.scope == undefined ){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("scope is missing in request object.",400,"invalid_request");
	}
	if ( claims.nonce == undefined ){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("nonce is missing in request object. ",400,"invalid_request");
	}
	if (claims.redirect_uri == undefined){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("redirect_uri in request object is missing. ",400,"invalid_request");
	}
	if (headers.alg == "none"){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("alg in request object value cannot be none. ",400,"invalid_request");
	}
    if (headers.alg == "RS256"){
	   OAuthMappingExtUtils.throwSTSCustomUserPageException("RS256 cannot be used to sign request object. ",400,"invalid_request");
	}
	/*
     * Check that the exp is not greater than 60 mins
     */

    if ( claims.exp != undefined ){
        var expDate = new Date(claims.exp * 1000);
		IDMappingExtUtils.traceString("expDate: " + expDate.getTime());
        var currDate = new Date();
		IDMappingExtUtils.traceString("currDate: " + currDate.getTime());
        var expTime = expDate.getTime() - currDate.getTime();
		IDMappingExtUtils.traceString("expTime: " + expTime);
		if (expTime >= 60*60*1000){
            OAuthMappingExtUtils.throwSTSCustomUserPageException("exp is greater than 60 mins.",400,"invalid_request");
		}
        else if (expDate < currDate){
            OAuthMappingExtUtils.throwSTSCustomUserPageException("Request object has expired.",400,"invalid_request");

       }
    }
    /*
     * Check that the nbf is not greater than 60 mins
     */
      if ( claims.nbf!= undefined ){
        var nbfDate = new Date(claims.nbf * 1000);
		IDMappingExtUtils.traceString("nbfDate: " + nbfDate.getTime());
        var currDate = new Date();
		IDMappingExtUtils.traceString("currDate: " + currDate.getTime());
        var nbfTime = currDate.getTime() - nbfDate.getTime();
		IDMappingExtUtils.traceString("nbfTime: " + nbfTime);
		if ( nbfTime > 60*60*1000){
            OAuthMappingExtUtils.throwSTSCustomUserPageException("nbf is greater than 60 mins.",400,"invalid_request");
		}
    }


	/*
	 * Validates aud and issuer value in request object against information in definition.
	 */
	if ( claims.iss != undefined ){
		var iss = OAuthMappingExtUtils.getDefinitionByID(defID).getOidc().getIss();

		if (Array.isArray(claims.aud)){
		   var found = false;
		   for (var x = 0; x < claims.aud.length; x++ ){
			   if( claims.aud[x]!= iss ){
					found = true;
			   }
		   }
		   if (!found){
			  OAuthMappingExtUtils.throwSTSCustomUserPageException("aud in request object does not match issuer of client definition.",400,"invalid_request");
		   }
		}
		else if( claims.aud != iss ){
			OAuthMappingExtUtils.throwSTSCustomUserPageException("aud in request object does not match issuer of client definition.",400,"invalid_request");
		}
	}

	/*
	 * Ensures Nonce/State length are within supported range, 255.
	 */
	if ( claims.state != undefined && claims.state.length > 255){
		OAuthMappingExtUtils.throwSTSCustomUserPageException("State in request object exceeds supported limit.",400,"invalid_request");
	}

	if ( claims.nonce != undefined && claims.nonce.length > 255){
		OAuthMappingExtUtils.throwSTSCustomUserPageException("Nonce in request object exceeds supported limit.",400,"invalid_request");
	}

}
