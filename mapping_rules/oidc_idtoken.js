// OIDCIDToken mapping rule.
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);

//IDMappingExtUtils.traceString("oidc_idtoken mapping rule called with stsuu: " + stsuu.toString());

/*
 * Defines mapping of id_token attributes we could have to the actual credential
 * attribute name in our ivcred
 */
var idTokenAttrsToCredAttrs = {
	"email" : "emailAddress",
	"given_name" : "firstName",
	"family_name" : "lastName"
};

/*
 * Defines which attrs are included based on which scopes are permitted by the
 * user.
 */
var scopeToIDTokenAttrs = {
	"profile" : [ "given_name", "family_name" ],
	"email" : [ "email" ]
};

/*
 * Iterate over all approved scopes. For each id_token attribute name associated
 * with an approved scope, look to see if the corresponding credential attribute
 * exists, and if so, include it's values in the output stsuu using the id_token
 * attribute name
 */
var finalAttrs = [];
var credAttributes = stsuu.getAttributeContainer();
var permittedScopes = stsuu.getContextAttributes().getAttributeValuesByName(
		"scope");
if (permittedScopes != null && permittedScopes.length > 0) {
	for (var i = 0; i < permittedScopes.length; i++) {
		var permittedIdTokenAttrs = scopeToIDTokenAttrs[permittedScopes[i]];
		if (permittedIdTokenAttrs != null && permittedIdTokenAttrs.length > 0) {
			for (var j = 0; j < permittedIdTokenAttrs.length; j++) {
				var idTokenAttrName = permittedIdTokenAttrs[j];
				var credAttrName = idTokenAttrsToCredAttrs[idTokenAttrName];
				var credAttrValues = credAttributes
						.getAttributeValuesByName(credAttrName);
				if (credAttrValues != null && credAttrValues.length > 0) {
					finalAttrs.push(new Attribute(idTokenAttrName, "",
							credAttrValues));
				}
			}
		}
	}
}

/*
 * Clear the attribute list
 */
stsuu.clearAttributeList();

/*
 * Add back in the final attributes
 */
for (var i = 0; i < finalAttrs.length; i++) {
	stsuu.addAttribute(finalAttrs[i]);
}

//IDMappingExtUtils.traceString("oidc_idtoken mapping rule finished with stsuu: " + stsuu.toString());
