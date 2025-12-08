importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry MMFA with TOTP Fallback");

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

var branchMap = {};
var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();

var username = checkLogin();

// If the user just authed with basicAuth, or authed with IVIA, or the user
// just performed a CI auth, you may pass!
if(username != null) {
    var mmfaRegistrations = MechanismRegistrationHelper.getMmfaRegistrationsForUser(username);
    var totpEnrolled = MechanismRegistrationHelper.isTotpEnrolled(username, getLocale());

    var decisionWasReturned = state.get("wasReset");
    IDMappingExtUtils.traceString("Returned to decision from initial branch: "+decisionWasReturned);

    if(!decisionWasReturned && mmfaRegistrations.length > 0) {
        IDMappingExtUtils.traceString("MMFA Registrations exist, try MMFA flow first.");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:mmfa"]);

        // Set a macro to inform the MMFA page if TOTP is enrolled
        macros.put("@TOTP_ENROLLED@", jsString(totpEnrolled));

        result = true;
    } else if(totpEnrolled) {
        IDMappingExtUtils.traceString("No MMFA Registrations, or decision returned. Try TOTP");
        state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:totp"]);
        result = true;
    } else {
        IDMappingExtUtils.traceString("No MMFA or TOTP enrollment. Throw an error.");
        macros.put("@ERROR_MESSAGE@", "no_second_factor");
        page.setValue("/authsvc/authenticator/error.html");
    }
}


// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit MMFA with TOTP Fallback");
