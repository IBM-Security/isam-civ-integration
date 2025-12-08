importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry FIDO2PAIR Authentication Decision");

var result = false;

var branchMap = {};

var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();

var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
var credAuthMethod = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "AZN_CRED_AUTH_METHOD");

IDMappingExtUtils.traceString("Username from request: " + username);

var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
IDMappingExtUtils.traceString("Type from request: " + type);
if (username != null && username != "" && credAuthMethod != "remember-me") {
    IDMappingExtUtils.traceString("User is already authenticated. Authentication Skipped.");
    state.put("skipDecision", "true");
    result = true;
}
else if (type == "fido2") {
    IDMappingExtUtils.traceString("Browser has a FIDO credential, and user chose to use FIDO");
    state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:fido2"]);
    if(credAuthMethod == "remember-me") {
        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
    }
    result = true;
} else if (type == "password") {
    IDMappingExtUtils.traceString("User chose to try Username/Password.");
    state.put("operation", "verify");
    state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:password"]);
    result = true;
}

if(username != null && username != "" && credAuthMethod == "remember-me") {
    macros.put("@PERSISTENT_USERNAME@", username);
}

var existingRego = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "existingRego");
IDMappingExtUtils.traceString("existingRego from request: " + existingRego);
if (existingRego != null) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "existingRego", existingRego);
}

success.setValue(result);
IDMappingExtUtils.traceString("Exiting FIDO2PAIR Authentication Decision");
