/*
* This mapping rule is a special-purpose rule for injecting samlp:Extension elements into a SAMLMessage.
* 
* Some SAML federation partners (particularly government-run or industry-specific require the use of these custom
* extensions to relay additional data about a federation relationship or runtime parameter. 
* These extensions are all defined by the SAML specification.
* 
* This example mapping rule shows how you can populate some locale information into the AuthnRequest as an extension.
* 
* What we get as "input" in this mapping rule is a context. The context contains a bunch of information about
* the current message that we can use to decide whether or not to even add extensions, and also use to determine
* what extensions or values to add. For example we could use the value of a HTTP header from the current request
* to select what language to ask the IDP to present a login form in.
* 
* The "output" from the mapping rule is XML nodes populated into the output variable "extension_properties". This begins
* as an empty java.util.List, and we populate it with one or more org.w3c.dom.Node objects.
*/
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

/**
 * This is really a debug/discovery function that logs everything we are allowed to get access to about
 * the current message. We could use any of this information to decide whether or not to add any
 * samlp:Extensions, and influence what those extensions might be.
 */
function logAvailableContext() {
	var str = 'logAvailableContext';
	// url
	str += "\n   Request URL: " + context.getUrl();
	
	// headers
	var headerList = context.getHeaderNames();
	for (var i = headerList.iterator(); i.hasNext(); ) {
		var n = i.next();
		var v = context.getHeader(n);
		str += "\n   Header with name: " + n + " value: " + v;
	}
	
	// parameters
	var paramList = context.getParameterNames();
	for (var i = paramList.iterator(); i.hasNext(); ) {
		var n = i.next();
		var v = context.getParameter(n);
		str += "\n    Parameter with name: " + n + " value: " + v;
	}
	
	// now the message "Info" keys and their values
	var keyList = context.getInfoKeys();
	for (var i = keyList.iterator(); i.hasNext(); ) {
		var n = i.next();
		var v = context.getInfoValue(n);
		str += "\n    Info element with key: " + n + " value: " + v;
	}
	IDMappingExtUtils.traceString(str);
}

/**
 * This function builds the list of nodes that are to go within the samlp:Extensions object of a message.
 * You could do this based on information available in the request, or statically. Have a look at the output
 * of logAvailableContext to get an idea of what you can see and make decisions about.
 * 
 * @returns nothing, but extension_properties will be updated with the nodes we want to add as children of
 * samlp:Extensions.
 */
function buildSAMLExtensions() {
	var d = IDMappingExtUtils.newXMLDocument();
	var e = d.createElementNS("request", "locale");
	e.setTextContent("en-US");
	
	extension_properties.add(e);
}

/**
 * This function returns true if this execution of the mapping rule should add samlp:Extensions nodes.
 * In the case of this example, we do that on any AuthnRequest.
 * @returns
 */
function shouldAddExtensions() {
	var msgType = context.getInfoValue("MsgType"); 
	return (msgType != null && msgType.equals("AuthnRequest"));
}

// main logic starts here
var debug = false;
if (debug) {
  // To see this debug ensure you have the following trace component enabled:
  // com.tivoli.am.fim.trustserver.sts.utilities.*=ALL
  //
  // To see how to enable trace on IVIA see: 
  // https://www.ibm.com/docs/en/sva/latest?topic=settings-runtime-parameters
	logAvailableContext();
}

if (shouldAddExtensions()) {
	buildSAMLExtensions();
}
