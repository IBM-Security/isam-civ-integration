importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);

function getACR(){
	var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();
	for (var i = 0; i < claims.length; i++) {
		var dialect = claims[i].getAttribute("Dialect");
		if ("urn:ibm:names:ITFIM:saml".equalsIgnoreCase(dialect)) {
			var requestedACs = claims[i].getElementsByTagName("samlp:RequestedAuthnContext");
			IDMappingExtUtils.traceString("requestedACs : " + requestedACs );
			if (requestedACs != null) {
				var requestedAC = requestedACs.item(0);
				if(requestedAC != null){
					var acrValues = requestedAC.getElementsByTagName("saml:AuthnContextClassRef");
					for (var k = 0; k < acrValues.getLength(); k++) {
						var acrValue = acrValues.item(k).getTextContent();
						IDMappingExtUtils.traceString("acrValue: " + acrValue);
					}
					return acrValue;
				}
			}
		}
	}
}

function getACDR(){
	var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();

	for (var i = 0; i < claims.length; i++) {
		var dialect = claims[i].getAttribute("Dialect");

		if ("urn:ibm:names:ITFIM:saml".equalsIgnoreCase(dialect)) {
			var requestedACs = claims[i].getElementsByTagName("samlp:RequestedAuthnContext");
			IDMappingExtUtils.traceString("requestedACs : " + requestedACs );
			if (requestedACs != null) {
				var requestedAC = requestedACs.item(0);
				if(requestedAC != null){
					var acdrValues = requestedAC.getElementsByTagName("saml:AuthnContextDeclRef");
					for (var k = 0; k < acdrValues.getLength(); k++) {
						var acdrValue = acdrValues.item(k).getTextContent();
						IDMappingExtUtils.traceString("acdrValue: " + acdrValue);
					}
					return acdrValue;
				}
			}
		}
	}
}

function getComparison(){
	var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();

	for (var i = 0; i < claims.length; i++) {
		var dialect = claims[i].getAttribute("Dialect");

		if ("urn:ibm:names:ITFIM:saml".equalsIgnoreCase(dialect)) {
			var requestedACs = claims[i].getElementsByTagName("samlp:RequestedAuthnContext");
			IDMappingExtUtils.traceString("requestedACs : " + requestedACs );
			
			if (requestedACs != null) {
				var requestedAC = requestedACs.item(0);
				if (requestedAC != null) {
					var comparison = requestedAC.getAttribute("Comparison");
					IDMappingExtUtils.traceString("comparison: " + comparison);
					return comparison;
				}
			}
			
		}
	}
}

function setACR(ACR){
    IDMappingExtUtils.traceString("Setting ACR to : " + ACR);
	var responseAcr = new Attribute("AssertionAuthnContextRef", "urn:oasis:names:tc:SAML:2.0:assertion", ACR);
	stsuu.addContextAttribute(responseAcr);
}

