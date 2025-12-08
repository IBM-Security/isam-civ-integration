importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);

/* This mapping rule contains an example to retrieve an assertion attribute that is in the EncryptedID format

Example:
	<stsuuser:Attribute name="urn:nl-eid-gdi:1.0:ActingSubjectID" type="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
		<stsuuser:Value>
			<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser</saml:NameID>
		</stsuuser:Value>
	</stsuuser:Attribute>

*/


/*
	Retrieve all the attributes
*/
var attributes = stsuu.getAttributes();

/*
	In this example the attribute we are looking for is as defined below, change it if required.
*/
var sampleAttr = "urn:nl-eid-gdi:1.0:ActingSubjectID";

var decryptedAttributeValue = null;

while (attributes.hasNext()) {
	var attr = attributes.next();
	/*
		Parsing through all the attributes to retrieve the desired attribute
	*/
	if(attr.getName() == sampleAttr){
		var nodeArray =  attr.getNodeValues()
		for (var i = 0; i < nodeArray.length; i++) 
		{ 
			var n = nodeArray[i]; 
			var foundLocalName = n.getLocalName();
			var foundNamespace = n.getNamespaceURI();
			/*
				Checking the name and the namespace of the node
			*/
			if(foundLocalName == "NameID" && foundNamespace == "urn:oasis:names:tc:SAML:2.0:assertion")
			{
				decryptedAttributeValue = n.getTextContent();
				IDMappingExtUtils.traceString("decryptedAttributeValue : "+decryptedAttributeValue );
			}
		} 
	}
}

if(decryptedAttributeValue != null){
	var encryptedIdAttr = new Attribute("encryptedIdAttr", "urn:oasis:names:tc:SAML:2.0:assertion", decryptedAttributeValue);
	stsuu.addAttribute(encryptedIdAttr);
}


