// SAML 2.0 Identity Provider mapping rule.

// This mapping rule can be used to customize the content of SAML assertion
// issued to Service Provider. IVIA provides an implicit object "stsuu", which
// represents the current IVIA credential.

// "stsuu" is an instance of STSUniversalUser Java class. You can find the
// javadoc of this class in Local Management Interface under Manage (System
// Settings) >> Secure Settings >> File Downloads. In File Downloads panel,
// download IVIA-javadoc.zip under federation >> doc. The javadoc of 
// STSUniversalUser class is located under com.tivoli.am.fim.sts directory.

/*
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Attribute);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.AttributeStatement);
*/

// Example: Setting name ID (i.e., NameID) of SAML assertion.
//
// To set name ID, add a principal attribute to "stsuu", as shown below. The
// attribute name must be "name". The type and value will be used as name ID
// format and value, respectively.

/*
stsuu.addPrincipalAttribute(new Attribute("name", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "john.doe@example.com"));
*/

// Example: Setting authentication context class reference
//          (i.e., AuthnContextClassRef) of SAML assertion.
//
// To set authentication context class reference of SAML assertion, add an
// attribute with name "AuthnContextClassRef" and type
// "urn:oasis:names:tc:SAML:2.0:assertion" to "stsuu", as shown below.

/*
stsuu.addAttribute(new Attribute("AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion", "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
*/

// Example: Setting authenticating authority (i.e., AuthenticatingAuthority) of
//          SAML assertion.
//
// To set authenticating authority of SAML assertion, add an attribute with
// name "AuthenticatingAuthority" and type 
// "urn:oasis:names:tc:SAML:2.0:assertion" to "stsuu", as shown below.

/*
stsuu.addAttribute(new Attribute("AuthenticatingAuthority", "urn:oasis:names:tc:SAML:2.0:assertion", "https://idp.example.com"));
*/

// Example: Adding attribute to SAML assertion.
//
// By default, SAML assertion contains only one attribute statement. To add an
// attribute to this attribute statement, add an attribute to "stsuu", as shown
// below. The "stsuu" attribute name and type will be used as the SAML
// attribute name and type. 

/*
stsuu.addAttribute(new Attribute("first_name", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", "john"));
stsuu.addAttribute(new Attribute("last_name",  "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", "doe"));
*/

// Example: Adding additional attribute statement (i.e., AttributeStatement) to
//          SAML assertion.
//
// By default, SAML assertion contains only one attribute statement. To add
// another attribute statement, add an attribute statement to "stsuu", as shown
// below.

/*
var attributeStatement = new AttributeStatement();
attributeStatement.addAttribute(new Attribute("email_address", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", "john.doe@example.com"));
attributeStatement.addAttribute(new Attribute("mobile_number", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", "12345678"));

stsuu.addAttributeStatement(attributeStatement);
*/

// Example: Retrieve HTTP request claim, which contains various information
//          about the incoming HTTP request (e.g., headers, cookies, POST
//          parameters, query string parameters). HTTP request claim can be
//          configured using advanced configurations under category
//          "sps.httpRequestClaims".

/*
var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();

for (var i = 0; i < claims.length; i++) {
    var dialect = claims[i].getAttribute("Dialect");

    if ("urn:ibm:names:ITFIM:httprequest".equalsIgnoreCase(dialect)) {
        var headers = claims[i].getElementsByTagName("Header");

        for (var j = 0; j < headers.getLength(); j++) {
            var header = headers.item(j);
            var name   = header.getAttribute("Name");
            var values = header.getElementsByTagName("Value");
            
            for (var k = 0; k < values.getLength(); k++) {
                var value = values.item(k).getTextContent();

                IDMappingExtUtils.traceString("Header with name [" + name + "] and value [" + value + "]");
            }
        }
    }
}
*/

// Example: Retrieve SAML claim, which contains various information about the
//          current SAML authentication flow (e.g., relay state, requested name
//          ID format, name ID, target). Note that claim available at Identity 
//          Provider and Service Provider may be different. See the trace.log
//          for the details.

/*
var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();

for (var i = 0; i < claims.length; i++) {
    var dialect = claims[i].getAttribute("Dialect");

    if ("urn:ibm:names:ITFIM:saml".equalsIgnoreCase(dialect)) {
        var samlClaims = claims[i].getElementsByTagName("Saml20Claims");

        for (var j = 0; j < samlClaims.getLength(); j++) {
            var samlClaim             = samlClaims.item(j);
            var relayState            = samlClaim.getAttribute("RelayState");
            var requestedNameIDFormat = samlClaim.getAttribute("RequestedNameIDFormat");

            IDMappingExtUtils.traceString("Relay state [" + relayState + "]");
            IDMappingExtUtils.traceString("Requested name ID format [" + requestedNameIDFormat + "]");

            var nameIDs = samlClaim.getElementsByTagName("NameID");

            for (var k = 0; k < nameIDs.getLength(); k++) {
                var nameID = nameIDs.item(k).getTextContent();

                IDMappingExtUtils.traceString("Name ID [" + nameID + "]");
            }
        }
    }
}
*/

// Example: Make basic HTTP GET call. If SSL protocol is used, IVIA will
//          validate the server certificate against truststore specified in
//          advanced configuration "util.httpClient.defaultTrustStore".

/*
var url      = "https://hostname/path";
var response = HttpClient.httpGet(url);
var data     = JSON.parse(response.getBody());

IDMappingExtUtils.traceString("JSON response [" + JSON.stringify(data) + "]");
*/

// Example: Make advanced HTTP POST call.

/*
var url        = "https://hostname/path";
var headers    = new Headers();
var parameters = new Parameters();
var trustStore = "my_trust_store";
var username   = "admin";
var password   = "admin";
var keyStore   = "my_key_store";
var keyAlias   = "my_key_alias";

headers.addHeader("Accept",       "application/json");
headers.addHeader("Content-Type", "application/x-www-form-urlencoded");

parameters.addParameter("email_address", "john.doe@example.com");

var response = HttpClient.httpPost(url, headers, parameters, trustStore, username, password, keyStore, keyAlias);
var data     = JSON.parse(response.getBody());

IDMappingExtUtils.traceString("JSON response [" + JSON.stringify(data) + "]");
*/


// Example: Per attribute encryption within a SAML2.0 assertion at the Identity provider 

/*
var encryptedAttribute = new Attribute("given_name", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", 
"testuser");
encryptedAttribute.setPreferEncryption(true);
stsuu.addAttribute(encryptedAttribute);
*/
