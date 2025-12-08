importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importPackage(Packages.com.ibm.security.access.httpclient);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);

function getRequestHeader(h) {
	return context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", h);
}

function addOptionalResponseAttribute(attrName, attrValue) {
	if (attrValue != null) {
		context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", attrName, attrValue);
	}
}

function jsToJavaArray(jsArray) {
	var javaArray = java.lang.reflect.Array.newInstance(java.lang.String, jsArray.length);
	for (var i = 0; i < jsArray.length; i++) {
		javaArray[i] = jsArray[i];
	}
	return javaArray;
}

var headerToAttribute = {
	"cert": "cert",
	"subjectcn": "SubjectCN",
	"fingerprint": "fingerprint",
	"subjectdn": "subjectDN",
	"issuerdn": "issuerDN",
	"subjectorganizationalunit": "subjectOU",
	"alternativednsname": "alternativeDNSName",
	"alternativeipaddress": "alternativeIPAddress",
	"alternativeuri": "alternativeURI",
	"alternativeemail": "alternativeEmail"
};

var headerMap = {};

Object.keys(headerToAttribute).forEach((x) => {
	let val = getRequestHeader(x);
	if (val != null) {
		headerMap[x] = ''+val;
	}
});

function addHeaderAttributesToCredential() {
	Object.keys(headerToAttribute).forEach((x) => {
		addOptionalResponseAttribute(headerToAttribute[x], headerMap[x]);
	});
}


IDMappingExtUtils.traceString("Entering FAPI_CertEAI Infomap");

// useful trace
IDMappingExtUtils.traceString("FAPI_CertEAI headers: " + JSON.stringify(headerMap));


if (headerMap["cert"] != null && headerMap["fingerprint"] != null && headerMap["subjectcn"] != null) {

	let authHeader = getRequestHeader("Authorization");

	//Check if there is a authorization header
	if (authHeader != null) {

		IDMappingExtUtils.traceString("Found authorization header, checking for access token");

		/*
		* This should be a resource request with the Authorization header representing the access_token.
		* Provided the access_token is valid, and the certificate-bound cnf checks out, we actually login 
		* as the resource owner identity associated with the access_token rather than as the certificate identity
		* which is that of the client.
		*/
                
		let array = authHeader.split(" ");
		if (array != null && array.length == 2 && array[0].equalsIgnoreCase("Bearer")) {
                        
			var accessToken = array[1];
			
			//Introspect the access_token
			let tkn = OAuthMappingExtUtils.getActiveToken(accessToken);
			if (tkn == null || tkn.isExpired() || !tkn.isEnabled()) {
				// unrecognized access token
				IDMappingExtUtils.traceString("Unrecognized bearer access token:: [" + accessToken + "]");
				success.setValue(false);

			} else {
				let cnf = OAuthMappingExtUtils.getAssociation(tkn.getStateId(), "cnf");
				let shouldLogin = true;
				if (cnf != null) {
					IDMappingExtUtils.traceString("cnf:: [" + cnf + "]");
					if (cnf != headerMap["fingerprint"]) {
						IDMappingExtUtils.traceString("Incoming Certificate thumbprint does not match certificate bound to token.");
						shouldLogin = false;
					} else {
						IDMappingExtUtils.traceString("Certificate bound check for access_token succeded, authenticating as resource owner");
					}						
				} else {
					IDMappingExtUtils.traceString("The access token is not certificate bound, authenticating as resource owner");
				}

				if (shouldLogin) {
					addOptionalResponseAttribute("username", tkn.getUsername());

					// make scope multi-valued
					context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attribute", "scope", tkn.getScope().split(" "));

					// set authentication level 2 so that access to protected OAuth resource works
					addOptionalResponseAttribute("AUTHENTICATION_LEVEL", "2");

					success.setValue(true);
				} else {
					success.setValue(false);
				}
						
			}
		} else {
			IDMappingExtUtils.traceString("Unable to parse authorization header");
			success.setValue(false);
		}
	} else {
		/*
		* No authorization header present, this is client authentication only
		*/
		IDMappingExtUtils.traceString("No authorization header present, authenticating as the client via MTLS");

		addHeaderAttributesToCredential();	

		//do not modify, this is to indicate MTLS client
		addOptionalResponseAttribute("username",  "__$mtls$__");
		
		success.setValue(true);
	}
}
else {
	IDMappingExtUtils.traceString("Certificate information unavailable");
	success.setValue(false);
}
