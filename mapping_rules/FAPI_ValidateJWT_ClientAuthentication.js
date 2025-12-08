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


/*
 * Check that the JWT has not expired 
 */
if ( claims.exp != undefined ){
    var expDate = new Date(claims.exp * 1000);
    var currDate = new Date();
    if (expDate < currDate){
        OAuthMappingExtUtils.throwSTSCustomUserPageException("Request object has expired.",400,"invalid_request");

   }
}


/*
 * Validates aud and issuer value in request object against information in definition.
 */
if ( claims.iss != undefined ){
    var defID = OAuthMappingExtUtils.getClient(claims.iss).getDefinitionID();
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


