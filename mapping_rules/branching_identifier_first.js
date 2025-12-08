importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.java.util.Base64);

importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry Branching Identifier First Authentication");

// The result of the decision. If false, the mapping rule will be run again. If true,
// a branch in the decision must be chosen, or the decision must be skipped.
var result = false;

var mmfaEnabled = true;
var fidoEnabled = true;
var fido2PAIREnabled = true;
var redirectEnabled = true;
var discoveryEnabled = true;

// The FIDO client needed for autofill FIDO Login
fido_client = fido2ClientManager.getClient("www.mmfa.ibm.com");

// The regex to match for the redirect flow, and the redirect URL.
var redirectRegex = [{"regex": "^[a-zA-Z0-9+_.-]+@example\\.ibm\\.com$", "url": "https://www.mmfa.ibm.com/saml/logininitial/?Username=%USERNAME%&NameIdFormat=Email&Target=https://www.mmfa.ibm.com"}];

// MMFA policy variables
var contextMessage = "Verify the sign-in on your device.";
var pushMessage = "Please verify that you are signing in.";
var signingAttributesList = "username, policyURI, pushMessage";

var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
var action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");

// Used to determine if FIDO assertion was completed.
var authenticatorData = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "authenticatorData");

// Used to allow the browser to switch from API requests (apiauthsvc) to browser requests (authsvc).
// The browser will send the FIDO result data via apiauthsvc, then the decision returns a JSON response
// while still in the decision, which allows the browser to switch to authsvc to complete the decision/policy.
var successParam = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "success");

var usernameFromSession = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
if (usernameFromSession != null && usernameFromSession != "") {
    IDMappingExtUtils.traceString("User is already authenticated. Skip further authentication.");
    state.put("skipDecision", "true");
    state.put("alreadyAuthed", "true");
    result = true;

} else if(action && action == "chooseAuth") {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    IDMappingExtUtils.traceString("User chose an authentiation method: " + type);

    if(type == "fido" && fidoEnabled) {
        state.put("decision", "FIDO Authentication");
        if(discoveryEnabled) {
            context.set(Scope.SESSION, "urn:ifa", "username", username);
        }
        result = true;

    } else if(type == "mmfa" && mmfaEnabled) {
        let mmfaRegistrations = state.get("mmfaRegistrations");
        if(mmfaRegistrations != null) {
            mmfaRegistrations = JSON.parse(mmfaRegistrations);
        } else {
            mmfaRegistrations = getMMFARegistrations(username);
        }

        let fingerprintEnrolled = mmfaRegistrations.some(function(registration) {
            return registration["fingerprintEnrolled"] == true;
        });
        IDMappingExtUtils.traceString("Does the user have a fingerprint method enrolled? " + JSON.stringify(fingerprintEnrolled));

        var policyURI = "urn:ibm:security:authentication:asf:mmfa_user_presence_response";
        if(fingerprintEnrolled) {
            policyURI = "urn:ibm:security:authentication:asf:mmfa_fingerprint_response";
        }

        context.set(Scope.SESSION, "urn:ifa", "contextMessage", contextMessage);
        context.set(Scope.SESSION, "urn:ifa", "pushMessage", pushMessage);
        context.set(Scope.SESSION, "urn:ifa", "signingAttributesList", signingAttributesList);
        context.set(Scope.SESSION, "urn:ifa", "policyURI", policyURI);
        if(discoveryEnabled) {
            context.set(Scope.SESSION, "urn:ifa", "username", username);
        }
        state.put("decision", "MMFA Authentication");
        result = true;

    } else if(type == "password") {
        state.put("decision", "Username Password");
        result = true;
    }

} else if(action && action == "cancel") {
    // Go back to the start
    IDMappingExtUtils.traceString("Cancel method choice, go back to username prompt.");
    page.setValue('/authsvc/authenticator/branching/identifier_first.html');
    if(fidoEnabled) {
        autofillFIDOOptions();
    }

} else if(authenticatorData != null && fidoEnabled) {
    IDMappingExtUtils.traceString("Autofill FIDO response, perform assertion results");
    autofillFIDOResult();

} else if(successParam != null && successParam == "success") {
    // Check FIDO is in completed mech types
    let authenticationMechanismTypes = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authenticationMechanismTypes");
    if(authenticationMechanismTypes.includes("urn:ibm:security:authentication:asf:mechanism:autofillFIDO")) {
        IDMappingExtUtils.traceString("Autofill FIDO was completed, skip the rest of the authentication decision");
        result = true;
        state.put("skipDecision","true");
    }
} else if(username) {
    IDMappingExtUtils.traceString("Check the username against regex, and fetch the user's registrations");

    let redirectMatched = false;
    if(redirectEnabled) {
        // Iterate over each entry in the regex array
        redirectRegex.some(function (entry) {
            if(entry.regex != null) {

                let regexp = new RegExp(entry.regex);
                if(regexp.test(username)) {
                    IDMappingExtUtils.traceString("Regex matched username, redirect the user now.");
                    macros.put("@IFA_REDIRECT_URL@", entry.url.replace("%USERNAME%", username));
                    macros.put("@USERNAME@", username);
                    page.setValue('/authsvc/authenticator/branching/ifa_redirect.html');
                    redirectMatched = true;
                }
            }
            return redirectMatched;
        });
    }

    if(!redirectMatched) {
        let fidoRegistrations = [];
        let mmfaRegistrations = [];
        let fingerprintEnrolled = false;

        if(discoveryEnabled) {
            fidoRegistrations = getFIDORegistrations(username);
            mmfaRegistrations = getMMFARegistrations(username);

            fingerprintEnrolled = mmfaRegistrations.some(function(registration) {
                return registration["fingerprintEnrolled"] == true;
            });
            IDMappingExtUtils.traceString("Does the user have a fingerprint method enrolled? " + JSON.stringify(fingerprintEnrolled));

            // Store MMFA registrations in state to save the DB hit later.
            state.put("mmfaRegistrations", JSON.stringify(mmfaRegistrations));

            IDMappingExtUtils.traceString("FIDO registrations: "+JSON.stringify(fidoRegistrations));
            IDMappingExtUtils.traceString("MMFA registrations: "+JSON.stringify(mmfaRegistrations));
        }

        // Set IS_FIDO = true if FIDO is enabled and we either have registrations, or discovery is disabled
        // i.e. if discovery is off, always prompt the user for FIDO.
        let isFIDO = fidoEnabled && (fidoRegistrations.length > 0 || !discoveryEnabled);

        // Return IS_MMFA = true if MMFA is enabled and we have registrations
        let isMMFA = mmfaEnabled && mmfaRegistrations.length > 0;

        macros.put("@USERNAME@", username);
        macros.put("@IS_FIDO@", isFIDO.toString());
        macros.put("@IS_MMFA@", isMMFA.toString());
        macros.put("@FINGERPRINT_PREFERRED@", fingerprintEnrolled.toString());
        page.setValue('/authsvc/authenticator/branching/ifa_choice.html');
    }

    // If FIDO2 PAIR is enabled, we need to store whether the browser is UVPA capable, and the existing
    // PAIR specific local storage data, so that the FIDO2 PAIR Prep mapping rule can determine if the
    // user should be prompted for registration.
    if(fido2PAIREnabled) {
        var isUVPACapable = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "uvpaCapable");
        if(isUVPACapable != null) {
            state.put("uvpaCapable", isUVPACapable);
        }
        var pairLocalStorageStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "pairLocalStorage");
        if(pairLocalStorageStr != null) {
            state.put("pairLocalStorage", pairLocalStorageStr);
        }
    }
} else if(fidoEnabled) {
    // Always get FIDO options on first run.
    IDMappingExtUtils.traceString("Autofill FIDO may be available, fetch assertion options");
    autofillFIDOOptions();
}

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit Branching Identifier First Authentication");

function autofillFIDOOptions() {
    var assertionOptions = JSON.parse(fido_client.assertionOptions(JSON.stringify({"userVerification":"required", "timeout":86400})));
    IDMappingExtUtils.traceString("FIDO Assertion Options: " + JSON.stringify(assertionOptions));
    var status = assertionOptions['status'];
    if (status == 'ok') {
        macros.put("@FIDO_RP_ID@", assertionOptions['rpId']);
        macros.put("@FIDO_TIMEOUT@", assertionOptions['timeout'].toString());
        macros.put("@FIDO_CHALLENGE@", assertionOptions['challenge']);
        macros.put('@FIDO_EXTENSIONS@', JSON.stringify(assertionOptions['extensions']));
        macros.put("@FIDO_USER_ID@", assertionOptions['userId'] == null ? "" : assertionOptions['userId']);
        macros.put("@FIDO_STATUS@", assertionOptions['status']);
        macros.put("@FIDO_USER_VERIFICATION@", assertionOptions['userVerification']);
        macros.put("@FIDO_ERROR_MESSAGE@", assertionOptions['errorMessage']);
        macros.put("@FIDO_ALLOW_CREDENTIALS@", assertionOptions['allowCredentials'] == null ? "[]" : JSON.stringify(assertionOptions['allowCredentials']));

    } else {
        macros.put("@FIDO_STATUS@", assertionOptions['status']);
        macros.put("@FIDO_ERROR_MESSAGE@", assertionOptions['errorMessage']);
        macros.put("@ERROR_MESSAGE@", assertionOptions['errorMessage']);
    }
}

function autofillFIDOResult() {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    var id = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "id");
    var rawId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "rawId");
    var clientDataJSON = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "clientDataJSON");
    var signature = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "signature");
    var userHandle = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "userHandle");
    var getClientExtensionResults = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "getClientExtensionResults");
    var extensions = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "extensions");
    var authenticatorAttachment = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "authenticatorAttachment");

    var assertion = {
        'type': ''+type,
        'id': ''+id,
        'rawId': ''+rawId,
        'response': {
            'clientDataJSON': ''+clientDataJSON,
            'authenticatorData': ''+authenticatorData,
            'signature': ''+signature,
            'userHandle': ''+userHandle
        }
    };
    if (getClientExtensionResults != null) {
        assertion['getClientExtensionResults'] = JSON.parse(getClientExtensionResults);
    }
    if (extensions != null) {
        assertion['extensions'] = JSON.parse(extensions);
    }
    if (authenticatorAttachment != null) {
        assertion['authenticatorAttachment'] = ''+authenticatorAttachment;
    }
    var assertionResult = JSON.parse(fido_client.assertionResult(JSON.stringify(assertion)));
    IDMappingExtUtils.traceString("FIDO Assertion Result: " + JSON.stringify(assertionResult));
    var status = assertionResult['status'];
    if (status == 'ok') {
        macros.put("@FIDO_STATUS@", "ok");
        if(assertionResult["user"] && assertionResult["user"]["name"]) {
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", assertionResult["user"]["name"]);
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authenticationMechanismTypes", "urn:ibm:security:authentication:asf:mechanism:autofillFIDO");

            // add any other mediator-populated credential attributes as well
            if (assertionResult.attributes != null && assertionResult.attributes.credentialData != null) {
                Object.keys(assertionResult.attributes.credentialData).forEach((key) => {
                    if (assertionResult.attributes.credentialData[key] != null) {
                        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", key, assertionResult.attributes.credentialData[key]);
                    }
                });
            }

            state.put("credentialId", id);

            if(authenticatorAttachment != null) {
                state.put("authenticatorAttachment", authenticatorAttachment);
            }
        }

    } else {
        IDMappingExtUtils.traceString("An error was encountered: " + assertionResult['errorMessage']);
        macros.put("@FIDO_STATUS@", assertionResult['status']);
        macros.put("@FIDO_ERROR_MESSAGE@", assertionResult['errorMessage']);
        macros.put("@ERROR_MESSAGE@", assertionResult['errorMessage']);
    }

    // If FIDO2 PAIR is enabled, we need to store whether the browser is UVPA capable, and the existing
    // PAIR specific local storage data, so that the FIDO2 PAIR Prep mapping rule can determine if the
    // user should be prompted for registration.
    if(fido2PAIREnabled) {
        var isUVPACapable = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "uvpaCapable");
        if(isUVPACapable != null) {
            state.put("uvpaCapable", isUVPACapable);
        }
        var pairLocalStorageStr = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "pairLocalStorage");
        if(pairLocalStorageStr != null) {
            state.put("pairLocalStorage", pairLocalStorageStr);
        }
    }
}


/**
 * Fetch the user's enrolled FIDO registrations
 */
 function getFIDORegistrations(username) {
    let registrations = [];
    let fidoRegistrations = MechanismRegistrationHelper.getFidoRegistrationsForUser(username);

    for(j = 0; j < fidoRegistrations.length; j++) {
        let registration = fidoRegistrations[j];
        registrations.push(JSON.parse(registration.toString()));
    };

    return registrations;
}

/**
 * Fetch the user's enrolled MMFA registrations
 */
function getMMFARegistrations(username) {
    let registrations = [];
    let mmfaRegistrations = MechanismRegistrationHelper.getMmfaRegistrationsForUser(username);

    for(j = 0; j < mmfaRegistrations.length; j++) {
        let registration = mmfaRegistrations[j];
        registrations.push(JSON.parse(registration.toString()));
    };

    return registrations;
}
