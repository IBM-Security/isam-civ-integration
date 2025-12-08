importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry IFA Prep FIDO2 PAIR");

// This mapping rule performs a series of checks on what has occured in the IFA policy, and what is currently
// stored in localStorage on the browser for FIDO2PAIR, and if a determination is made that FIDO2PAIR solicited
// registration can be skipped, we set the existingRego cred attribute which is one of the conditions already
// checked by the FIDO2PAIR_Reg_Decision mapping rule.

var skipSolicitedRegistration = false;
var username = jsString(context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username"));

if (!skipSolicitedRegistration) {
    // This check looks at the fidoUsersObject gathered from localStorage on the browser if it exists.
    // if so, and there is an entry for the current user, then either they have a registration or have 
    // opted out - either way that is a condition for skipping
    var pairLocalStorageStr = state.get("pairLocalStorage");
    if (pairLocalStorageStr != null && pairLocalStorageStr != "") {
        var fidoUsersObject = JSON.parse(pairLocalStorageStr);
        if (fidoUsersObject.fidoUsers && fidoUsersObject.fidoUsers.find(user => 
                (user.username != null && user.username != "" && user.username.toLowerCase() === username.toLowerCase()))) {
            IDMappingExtUtils.traceString("Skipping solicited registration because user found in localStorage: " + username);
            skipSolicitedRegistration = true;
        }
    }
}

if (!skipSolicitedRegistration) {
    // This check determines if during IFA the user has logged in with a platform authenticator
    // that may be done in either the autofill UI at the start, or if the user explicitly chose FIDO2 authentication
    var authenticatorAttachment = state.get("authenticatorAttachment");
    if (authenticatorAttachment == "platform") {
        IDMappingExtUtils.traceString("Skipping solicited registration because user performed platform authenticator login: " + username);
        skipSolicitedRegistration = true;
    }
}

if (!skipSolicitedRegistration) {
    // this check determines if the browser reported whether or not a platform authenticator is even available
    // if it is not, there is no point in doing solicited enrollment
    var isUVPACapable = state.get("uvpaCapable");
    if (isUVPACapable == "false") {
        IDMappingExtUtils.traceString("Skipping solicited registration because browser did not detect a user-verifying platform authenticator");
        skipSolicitedRegistration = true;
    }
}

// set the flag to skip if we have decided no need to solicit registration
if (skipSolicitedRegistration) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "existingRego", "true");
}

success.setValue(true);
IDMappingExtUtils.traceString("Exit IFA Prep FIDO2 PAIR");
