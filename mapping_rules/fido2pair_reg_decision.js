importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry FIDO2PAIR Registration Decision");

var result = false;

var branchMap = {};

var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();

var username = checkLogin();

if (username != null) {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    var skip = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "skip");
    var existingRego = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "existingRego");
    IDMappingExtUtils.traceString("Type from request: " + type);
    IDMappingExtUtils.traceString("Skip from request: " + skip);
    IDMappingExtUtils.traceString("ExistingRego from session: " + existingRego);
    macros.put("@USERNAME@", username);
    if (type == "fido2") {
        IDMappingExtUtils.traceString("Registering FIDO UVPA.");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:fido2registration"]);
        result = true;
    } else if (skip == "skip" || existingRego == "true") {
        IDMappingExtUtils.traceString("FIDO2 UVPA Registration Skipped.");
        state.put("skipDecision", "true");
        result = true;
    }
}

success.setValue(result);
IDMappingExtUtils.traceString("Exiting FIDO2PAIR Registration Decision");
