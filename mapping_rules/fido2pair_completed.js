importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

var successFIDO = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "successFIDO");
IDMappingExtUtils.traceString("success from request: " + successFIDO);

macros.put("@FIDO_STATUS@", "ok");

// Only set the eai flags on a registration flow. We only hit the registration flow if
// existingRego is false.
var existingRego = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "existingRego");
IDMappingExtUtils.traceString("ExistingRego from session: " + existingRego);
if (existingRego != null && existingRego == "false") {
    responseHeaders.put("am-eai-flags", "remember-session,success-page-response");
    IDMappingExtUtils.traceString("Set remember session, success page.");
}

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(successFIDO == "success");