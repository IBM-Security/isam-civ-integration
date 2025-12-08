importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("entry USC_Passkey_Success.js");

// Populate the page macros.
var username = state.get("username");
var firstName = state.get("firstName");

IDMappingExtUtils.traceString("Populating macros:");
IDMappingExtUtils.traceString("@USERNAME@ = "+username);
IDMappingExtUtils.traceString("@FIRSTNAME@ = "+firstName);

macros.put("@USERNAME@", username);
macros.put("@FIRSTNAME@", firstName);

// Indicate to the AuthSvc that we are finished and do not want to create a session.
success.endPolicyWithoutCredential();

IDMappingExtUtils.traceString("exit USC_Passkey_Success.js");
