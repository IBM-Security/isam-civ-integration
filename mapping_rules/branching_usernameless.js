importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry Branching Username-less");

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

var branchMap = {};
var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();

var decisionWasReturned = state.get("wasReset");
IDMappingExtUtils.traceString("Returned to decision from initial branch: "+decisionWasReturned);

if(decisionWasReturned) {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    IDMappingExtUtils.traceString("Type from request: "+type);

    if(type == "fido2") {
        IDMappingExtUtils.traceString("User chose to try FIDO2.");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:fido2"]);
        result = true;
    } else if(type == "password") {
        IDMappingExtUtils.traceString("User chose to try Username/Password.");
        state.put("operation", "verify");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:password"]);
        result = true;
    } else {
        // Invalid, reload QR Code
        IDMappingExtUtils.traceString("User chose invalid type, return to QR Code.");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:qrcode"]);
        result = true;
    }
} else {
    IDMappingExtUtils.traceString("Try QR Code Login flow first.");
    state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:qrcode"]);
    result = true;
}

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit Branching Username-less");
