importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);

//IDMappingExtUtils.traceString("oidc_rp mapping rule called with stsuu: " + stsuu.toString());

/*
 * Construct a basic identity made up of iss and sub
 */ 

var iss = stsuu.getAttributeContainer().getAttributeValueByName("iss");
var sub = stsuu.getAttributeContainer().getAttributeValueByName("sub");

/*
 * This builds a principal name from the iss and sub fields of the id_token. If
 * this user does not exist in the IVIA registry, either modify to map to a
 * local user that is in the registry, or change the EAI authentication
 * settings of the federation runtime to use PAC authentication. To use PAC
 * authentication, modify the following Federation -> Advanced Configuration:  
 *
 * poc.signIn.credResponseHeader = am-eai-pac 
 */
stsuu.setPrincipalName(iss + "/" + sub);

/*
 * Attributes from id_token come as Attributes - copy those we want to AttributeList
 * to be built into the credential. You can add to this list if you know what is in
 * the id_token you expect. Only those with values will be copied.
 */
var attrNames = [ 
	// these are standard claims
	"given_name", 
	"family_name",
	"name",
	"email",
	"access_token"
];
var finalAttrs = [];

for (var i = 0; i < attrNames.length; i++) {
	var attr = stsuu.getAttributeContainer().getAttributeByName(attrNames[i]);
	if (attr != null) {
		finalAttrs.push(attr);
	}
}
stsuu.clearAttributeList();

/*
 * Add back in the final attributes
 */
for (var i = 0; i < finalAttrs.length; i++) {
	stsuu.addAttribute(finalAttrs[i]);
}


/*
* Also pull these from context attributes (these are not available in the id_token)
*/
var contextAttrNames = [
    "access_token",
    "expires_in", 
    "scope"
];

for (var i = 0; i < contextAttrNames.length; i++) {
    var attr = stsuu.getContextAttributes().getAttributeByName(contextAttrNames[i]);
    if (attr != null) {
            stsuu.addAttribute(attr);
            stsuu.getContextAttributes().removeAttribute(attr);
    }
}



//IDMappingExtUtils.traceString("oidc_rp mapping rule finished with new stsuu: " + stsuu.toString());

