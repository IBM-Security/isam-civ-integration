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

IDMappingExtUtils.traceString("Entering validateSSA");

var claims_str = stsuu.getContextAttributes().getAttributeValueByNameAndType("claim_json", "urn:com:ibm:JWT");
var claims = JSON.parse(claims_str);
var header_str = stsuu.getContextAttributes().getAttributeValueByNameAndType("header", "urn:com:ibm:JWT");
var headers = JSON.parse(header_str);



if (headers.alg == "none"){
   reportError("Software statement is not signed");
}
if (headers.alg == "RS256"){
   reportError("RS256 cannot be used to sign Software statement.");
}
/*
 * Check that the exp is not greater than 10 mins
 */

if ( claims.exp != undefined ){
	var expDate = new Date(claims.exp * 1000);
	IDMappingExtUtils.traceString("expDate: " + expDate.getTime());
	var currDate = new Date();
	IDMappingExtUtils.traceString("currDate: " + currDate.getTime());
	var expTime = expDate.getTime() - currDate.getTime();
	IDMappingExtUtils.traceString("expTime: " + expTime);
	if (expTime >= 10*60*1000){
		reportError("Software Statement is invalid");
	}
	else if (expDate < currDate){
		reportError("Software Statement has expired.");

   }
}
/*
 * Check software_id
 */
if ( claims.software_id != undefined ){

	var subjectCN = stsuu.getAttributeValueByName("SubjectCN");
	IDMappingExtUtils.traceString("SubjectCN : validateSSA:"+subjectCN);
	var organizationUnit = stsuu.getAttributeValueByName("OrganizationUnit");
	IDMappingExtUtils.traceString("OrganizationUnit: validateSSA:"+OrganizationUnit+":claims.software_id:"+claims.software_id+":org_id:"+claims.org_id);
	if( subjectCN != claims.software_id){
		reportError("Software Statement signature is invalid.");
	}
	if( organizationUnit != claims.org_id){
		reportError("Software Statement signature is invalid.");
	}
}

if ( claims.software_redirect_uris != undefined ){
	var override_redirect_uri = new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("override_redirect_uri", "urn:ibm:names:ITFIM:oauth:body:param", claims.software_redirect_uris);
	stsuu.addContextAttribute(override_redirect_uri);  
}

function reportError(message){
	OAuthMappingExtUtils.throwSTSCustomUserPageException(message,400,"invalid_software_statement");
}
