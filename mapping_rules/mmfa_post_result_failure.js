// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

IDMappingExtUtils.traceString("Entry post MMFA fail infomap");

// Get the user action and update the MACRO
var denyReason = context.get(Scope.SESSION, "urn:ibm:security:asf:mmfa", "denyReason");
IDMappingExtUtils.traceString("Deny reason : " + denyReason);
macros.put("@DENY_REASON@", denyReason);

// Get the MMFA error message and update the MACRO
var errorMsg = context.get(Scope.SESSION, "urn:ibm:security:asf:mmfa", "mmfa_error_message");
IDMappingExtUtils.traceString("Error message : " + errorMsg);
macros.put("@ERROR_MESSAGE@", errorMsg);

success.setValue(false);
success.endPolicyWithoutCredential();
page.setValue("/authsvc/authenticator/mmfa/error.html");