// SAML 2.0 Service Provider mapping rule.

// This mapping rule can be used to customize the content of IVIA credential
// created based on incoming SAML assertion. IVIA provides an implicit object 
// "stsuu", which represents the current IVIA credential.

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
importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Group);
*/

// Example: Adding attribute to IVIA credential.
//
// To add attribute to IVIA credential, add an attribute to "stsuu", as shown
// below. Set the type to "urn:ibm:names:ITFIM:5.1:accessmanager".

/*
stsuu.addAttribute(new Attribute("first_name", "urn:ibm:names:ITFIM:5.1:accessmanager", "john"));
stsuu.addAttribute(new Attribute("last_name",  "urn:ibm:names:ITFIM:5.1:accessmanager", "doe"));
*/

// Example: Adding group to IVIA credential.
//
// To add attribute to IVIA credential, add an attribute to "stsuu", as shown
// below. Set the type to "urn:ibm:names:ITFIM:5.1:accessmanager", and the
// attributes to NULL.

/*
stsuu.addGroup(new Group("manager", "urn:ibm:names:ITFIM:5.1:accessmanager", null))
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
        var samlClaims = claims[i].getElementsByTagName("fimc:Saml20Claims");

        for (var j = 0; j < samlClaims.getLength(); j++) {
            var samlClaim  = samlClaims.item(j);
            var relayState = samlClaim.getAttribute("RelayState");
            var target     = samlClaim.getAttribute("Target");

            IDMappingExtUtils.traceString("Relay state [" + relayState + "]");
            IDMappingExtUtils.traceString("Target [" + target + "]");
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