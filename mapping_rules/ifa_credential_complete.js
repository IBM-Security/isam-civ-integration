importPackage(Packages.com.tivoli.am.fim.registrations);
importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

var successParam = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "success");
var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
var completedMechsArr = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attribute", "authenticationMechanismTypes");
var completedAuthMechs = [];
var requestBody = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "requestBody");
if(requestBody != null && requestBody != "") {
    requestBody = JSON.parse(requestBody);
}
var alreadyAuthed = state.get("alreadyAuthed");
if(alreadyAuthed == "true") {
    successParam = "success";
} else {
    for(i=0; i < completedMechsArr.length; i++) {
        completedAuthMechs.push("" + completedMechsArr[i]);
    }
    completedAuthMechs = JSON.stringify(completedAuthMechs);

    // Normal FIDO and Username/Password run through this mapping rule twice, whereas autofill FIDO and MMFA only run through once.
    if(successParam != "success" || completedAuthMechs.includes("urn:ibm:security:authentication:asf:mechanism:autofillFIDO") || completedAuthMechs.includes("urn:ibm:security:authentication:asf:mechanism:mmfa")) {

        // Add the FIDO registration used to the cred
        if(completedAuthMechs.includes("urn:ibm:security:authentication:asf:mechanism:fido2") || completedAuthMechs.includes("urn:ibm:security:authentication:asf:mechanism:autofillFIDO")) {
            // For normal FIDO, scrape the ID from the last FIDO request
            var completedCredId = requestBody["id"];

            // For autofill FIDO, scrape the ID from the mapping rule state (set in the decision).
            if(completedAuthMechs.includes("urn:ibm:security:authentication:asf:mechanism:autofillFIDO")) {
                completedCredId = state.remove("credentialId");
            }

            if(completedCredId != null) {
                let fidoRegistrations = getFIDORegistrations(username);
                let fidoRegistration = fidoRegistrations.filter(registration => {return registration.credentialId == completedCredId;});
                if(fidoRegistration.length > 0) {
                    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "fido.registration", JSON.stringify(fidoRegistration[0]));
                }
            }

            // For normal FIDO, scrape the authenticator attachment from the last FIDO request, otherwise
            // try getting it from state (autofill FIDO sets it that way)
            // We leave it in state, because it is also read by the IFA_Prepare_FIDO2PAIR  mapping rule
            var authenticatorAttachment = requestBody["authenticatorAttachment"];
            if (authenticatorAttachment != null) {
                state.put("authenticatorAttachment", authenticatorAttachment);
            } else {
                authenticatorAttachment = state.get("authenticatorAttachment");
            }

            // Set authenticatorAttachment if available as a cred attribute for demonstration purposes
            if(authenticatorAttachment != null) {
                context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "fido.authenticatorAttachment", authenticatorAttachment);
            }

        } else if(completedAuthMechs.includes("urn:ibm:security:authentication:asf:mechanism:mmfa")) {
            // For MMFA, find the transaction ID from the cred, and use it to look up the transaction data.
            var transactionId = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mmfa.authenticationTransactionId");
            var transaction = MechanismRegistrationHelper.getMMFATransaction(transactionId);
            var transactionObj = JSON.parse(transaction.toString());
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mmfa.transaction", transaction.toString());

            // Now check the transaction data for the authenticator ID.
            var authenticatorAttribute = transactionObj["attributes"].filter(attribute => {return Object.keys(attribute)[0] == "mmfa.request.authenticator.id";});
            if(authenticatorAttribute != null && authenticatorAttribute.length > 0) {
                // Attribute is formatted like: [{"mmfa.request.authenticator.id":["uuid70ed6708-73ea-4546-ba2c-d0b443401d51"]}] 
                var authenticatorId = authenticatorAttribute[0]["mmfa.request.authenticator.id"][0];
                let mmfaRegistrations = getMMFARegistrations(username);
                let mmfaRegistration = mmfaRegistrations.filter(registration => {return registration.authenticatorId == authenticatorId;});
                context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mmfa.registration", JSON.stringify(mmfaRegistration));
            }
        }
    }
}

// Set result. Either true for stop running this rule, or false for run the rule again.
success.setValue(successParam == "success");


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
