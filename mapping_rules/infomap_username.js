importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.


// Infomap Example username mapping rule.
//
// This example mapping rule makes use of the PluginUtils to check a user
// exists in the registry. 
//
// A mapping rule invoked by the InfoMap authentication mechanism has the following parameters available
//
// Input:
//
// var:context - type:Context -  the same session context which is passed into the
// authsvc_credential mapping rule. Makes available the users session
// attributes. May be null if unauthenticated. 
//
// var:state - type:Map - Any values placed in the users state by prior invocations of
// this instance of the InfoMap authentication mechanism.
// Will not be null
//
// Output:
//
// var:page - type:String - The page template to be displayed if this rule
// returns false, modify to return a different page. Will be populated with the
// configured page, overwrite to change.
//
// var:macros - type:Map<String, String> - Values to populate on the returned
// template page. Is an empty map passed in.
//

function isUsernameValid() {
	// Implement username validation here
	return true;
}


var param = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
IDMappingExtUtils.traceString("got a username: " + param);
if(param != null && param != "") {
	isValid = isUsernameValid(param);

	if(isValid) {
		success.setValue(true);
		context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", param);
	} else {
		success.setValue(false);
		macros.put("@ERROR_MESSAGE@","Invalid username");
	}
}


