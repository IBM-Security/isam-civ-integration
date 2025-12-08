importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry USC_Passkey_Reg_Decision.js");

var result = false;

var branchMap = {};
var mechanisms = [];
[mechanisms, branchMap] = getMechanismsAndBranchMap();

var username = state.get("username");

if (username != null) {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    var passCollected = state.get("passCollected");
    var uvpaCapable = state.get("uvpaCapable");

    IDMappingExtUtils.traceString("Type from request: " + type);
    IDMappingExtUtils.traceString("Pass collected from state: " + passCollected);
    IDMappingExtUtils.traceString("UVPA capable from state: " + uvpaCapable);

    macros.put("@USERNAME@", username);

    if (type == "fido2") {
        IDMappingExtUtils.traceString("Registering FIDO UVPA.");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:fido2registration"]);
        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
        result = true;

    } else if (type == "password") {
        // Check if we've already gathered password. It's important that we only ever skip decisions based
        // on server decided information, and not on request payload attributes.
        if (passCollected == true) {
            IDMappingExtUtils.traceString("Password already added, skip decision.");
            state.put("skipDecision", "true");
            result = true;

        } else {
            IDMappingExtUtils.traceString("Choose password branch.");
            state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:uscPasskeyCollectPassword"]);
            result = true;
        }

    } else if (passCollected == true && uvpaCapable == false) {
        IDMappingExtUtils.traceString("Password already added and no UVPA possible, skip decision.");
        state.put("skipDecision", "true");
        result = true;
    }
}

success.setValue(result);
IDMappingExtUtils.traceString("Exit USC_Passkey_Reg_Decision.js");
