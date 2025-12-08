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

IDMappingExtUtils.traceString("Entering validate DCR request");
var claims_str = stsuu.getContextAttributes().getAttributeValueByNameAndType("claim_json", "urn:com:ibm:JWT");
var claims = JSON.parse(claims_str);
var header_str = stsuu.getContextAttributes().getAttributeValueByNameAndType("header", "urn:com:ibm:JWT");
var headers = JSON.parse(header_str);


/**
 * You can turn on this to validate the algorithm used
 * Set the allowed algs 
 * In the openbankingUK, the RS256 is not allowed. 
 */
var validate_algs = true;
var allowed_algs = ["PS256", "ES384"];

if (validate_algs) {
	if(allowed_algs.indexOf(headers.alg)==-1){
	   reportError(headers.alg + " cannot be used to sign DCR request.");
	}
}

/*
 * Turn on this validation to check the lifetime of the exp
 * The lifetime is calculated based on the difference between <exp and cur> &&<curr,  iat/nbf>
 * Specification: https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-model
 */
var validate_expiry = true;
var clockskew = 3600; //in seconds

if (validate_expiry) {
	if ( claims.exp ){
		var expDate = new Date(claims.exp * 1000);
		IDMappingExtUtils.traceString("expDate: " + expDate.getTime());
		var currDate = new Date();
		IDMappingExtUtils.traceString("currDate: " + currDate.getTime());
		var expTime = expDate.getTime() - currDate.getTime();
		IDMappingExtUtils.traceString("expTime: " + expTime);
		if (expTime >= clockskew *1000){
			reportError("DCR request is invalid");
		}
		else if (expDate < currDate){
			reportError("DCR request has expired.");

	   }
	}
}

/*
 * accroding to the https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-model, iat no need to be validated, 
 * for other spec, it might be 
 * Turn on this validation to check the lifetime of the iat
*/
var validate_nbf = false;
if (validate_nbf) {
	if ( claims.nbf || claims.iat ){
		var start = claims.nbf || claims.iat;
		var startDate = new Date(start * 1000);
		IDMappingExtUtils.traceString("nbf / iat : " + startDate.getTime());
		var currDate = new Date();
		IDMappingExtUtils.traceString("currDate: " + currDate.getTime());
		var duration = currDate.getTime() - startDate.getTime();
		IDMappingExtUtils.traceString("duration: " + duration);
		if (duration >= clockskew *1000){
			reportError("DCR request is invalid");
		}
	}
}

/*
 * Turn on this validation to check the lifetime of response_types 
 * The response_types can only be code or code id_token
 * Specification: https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-model
 */
var validate_response_types = true;
	if(validate_response_types){
	var types = typeof claims.response_types;
	IDMappingExtUtils.traceString("claims.response_types types : " + types  , java.util.logging.Level.INFO);
	IDMappingExtUtils.traceString("claims.response_types : " + claims.response_types.length, java.util.logging.Level.INFO);
	if(claims.response_types && typeof claims.response_types ==='object'){
	      for (var i = 0 ; i < claims.response_types.length ; i++){
		      IDMappingExtUtils.traceString("claims.response_types : " + claims.response_types[i] , java.util.logging.Level.INFO);
		      if(claims.response_types[i]!="code" && claims.response_types[i]!="code id_token"){
		            reportError("Invalid response types");
		      }
	      }
	}
}


/*
 * Turn on this validation to check iss validity 
 * The iss' length can only range from 1 to 22, alphanumeric
 * Specification: https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-model
 */
var validate_iss = true;
if(validate_iss){
	if(!claims.iss || claims.iss.length < 1 || claims.iss.length >22 ||  /[^a-zA-Z0-9]/.test(claims.iss) ) {
		       reportError("iss is not valid");
	}
}


function reportError(message){
	OAuthMappingExtUtils.throwSTSCustomUserPageException(message,400,"invalid_software_statement");
}
