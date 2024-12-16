importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.

// This function can be used to add prefixes or suffixes to the username provided by 
// WebSEAL or the user. By default, it just returns the username;
function usernameMapping(username) {
    var mappedUsername = username;

    // We could simply add an email suffix:
    //mappedUsername += "@au1.ibm.com";

    // Or we could even add a realmName for federated CI users
    //mappedUsername += "@www.ibm.com";

    state.put("originalUsername", username);
    state.put("mappedUsername", mappedUsername);

    return mappedUsername;
}

function checkLogin() {
    IDMappingExtUtils.traceString("Check login");
    var sessionUsername = getUsernameFromSession();
    var username = getUsername();

    // If we have the username from the WebSEAL session, return immediately.
    if(sessionUsername != null) {
        return usernameMapping(sessionUsername);
    }

    // If we have no username from either session, state, or parameter, return 
    // a login page.
    if(username == null) {
        page.setValue("/authsvc/authenticator/ci/login.html");
        macros.put("@ERROR_MESSAGE@", errorMessages["user_not_found"]);
        return null;
    }

    // We've been given the username. Check if username/password auth has already
    // been done successfully for this session by fetching basicAuth from the
    // state map.
    var basicAuth = state.get("basicAuth");
    var password = getPassword();

    if(basicAuth != null && basicAuth == username) {
        return username;
    } else if(password != null) {
        var mappedUsername = usernameMapping(username);
        // If we were given the password as well, attempt auth.
        var justAuthed = CiClientV2.basicAuthentication(conn, mappedUsername, password, getLocale());
        if(justAuthed) {
            // If successful, save the just authed username as "basicAuth" in
            // the state map.
            state.put("basicAuth", mappedUsername);
            return mappedUsername;
        } else {
            // The login request failed. Return an error page via our handleError
            // method.
            handleError(errorMessages["login_failed"], null);
            return null;
        }
    } else if(username != null) {
        IDMappingExtUtils.traceString("Username provided, but no password");
        // We have a username but no password. Return a login page.
        macros.put("@USERNAME@", username);
        page.setValue("/authsvc/authenticator/ci/login.html");
        return null;
    }
}

function getUserId(conn, username) {
    IDMappingExtUtils.traceString("Get user ID");
    var userId = state.get("userId");
    if(userId == null) {
        var user = CiClientV2.getUser(conn, username, getLocale());
        if (user != null) {
            // We've successfully gotten the user ID. Save it and the username
            // in the state map.
            var userObj = JSON.parse(user);
            userId = userObj.id;
            state.put("userId", userId);
            state.put("username", username);

            // Also fetch some details to display on the USC page.
            var emails = userObj.emails;
            if(emails != null && emails.length > 0) {
                state.put("email", emails[0].value);
                macros.put("@EMAIL@", emails[0].value);
            }

            // This will store the user's mobile number.
            getMobileNumber(userObj);

            // We have two options here for a nice display name for the
            // user. We could use the givenName, or the formatted name. The
            // formatted name can be manually modified by the CI
            // administrator to be correct per the user's culture, but
            // defaults to givenName lastName if not provided. So we will
            // use givenName by default. To use the formatted name instead,
            // change name.givenName to name.formatted
            if(userObj.name != null && userObj.name.givenName != null) {
                state.put("name", userObj.name.givenName);
                macros.put("@NAME@", userObj.name.givenName);
            }
        } else {
            // The request failed. Return an error page via our handleError
            // method.
            handleError(errorMessages["user_not_found"], null);
        }
    } else {
        // If we already have the user ID, we should already have the email
        // and name saved. Fetch them to display on the USC page.
        var email = state.get("email");
        var name = state.get("name");
        if(email != null) {
            macros.put("@EMAIL@", email);
        }
        if(name != null) {
            macros.put("@NAME@", name);
        }
    }
    return userId;
}

/**
 * Check the given response for an error message. Overwrite errMessage if it's
 * included.
 */
function handleError(errMessage, resp) {
    var errorMessage = errMessage;

    if(resp != null) {
        IDMappingExtUtils.traceString("Error response: "+resp.getCode());
        IDMappingExtUtils.traceString("Error response body: "+resp.getBody());
        var json = getJSON(resp);

        if(json != null && json.messageDescription != null) {
            errorMessage = json.messageDescription;

            if(json.messageId != null) {
                errorMessage = json.messageId + " " + errorMessage;
            }
        }
    }

    macros.put("@ERROR_MESSAGE@", errorMessage);
    page.setValue("/authsvc/authenticator/ci/error.html");
}

/**
 * Get the type from the state or from the request.
 */
function getType() {
    var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
    if(type == null) {
        type = state.get("type");
    }
    return jsString(type);
}

/**
 * Get the OTP delivery detail from the session or from the request.
 */
function getOTPDelivery() {
    var otpDelivery = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "otpDelivery");
    if(otpDelivery == null) {
        otpDelivery = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otpDelivery");
    }
    return jsString(otpDelivery);
}

/**
 * Get the mobile number from the state or from the given user object.
 */
function getMobileNumber(user) {
    var otpDelivery = state.get("mobileNumber");
    if(otpDelivery == null) {
        if(user != null) {
            if(user.phoneNumbers != null && user.phoneNumbers.length > 0) {
                for(var i = 0; i < user.phoneNumbers.length; i++) {
                    if(user.phoneNumbers[i].type == "mobile") {
                        otpDelivery = user.phoneNumbers[i].value;
                        if(otpDelivery != null && otpDelivery != "") {
                            state.put("mobileNumber", otpDelivery);
                        }
                        break;
                    }
                }
            }
        }
    }
    return jsString(otpDelivery);
}

/**
 * Get the email address from the state or from the given user object.
 */
function getEmailAddress(user) {
    var otpDelivery = state.get("email");
    if(otpDelivery == null) {
        if(user != null) {
            if(user.emails != null && user.emails.length > 0) {
                otpDelivery = user.emails[0].value;
                state.put("email", otpDelivery);
            }
        }
    }
    return jsString(otpDelivery);
}

/**
 * Get the mobile number from the session or from the request.
 */
function getMobileNumberFromCredential() {
    var otpDelivery = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mobileNumber");
    if(otpDelivery == null) {
        otpDelivery = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "mobileNumber");
    }
    return jsString(otpDelivery);
}

/**
 * Get the email from the session or from the request.
 */
function getEmailAddressFromCredential() {
    var otpDelivery = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "emailAddress");
    if(otpDelivery == null) {
        otpDelivery = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "emailAddress");
    }
    return jsString(otpDelivery);
}

/**
 * Get the ID from the state or from the request.
 */
function getId() {
    var id = state.get("id");
    if(id == null) {
        id = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "id");
    }
    return jsString(id);
}

/**
 * Get the authenticator ID from the state or from the request.
 */
function getAuthenticatorId() {
    var authenticatorId = state.get("authenticatorId");
    if(authenticatorId == null) {
        authenticatorId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "authenticatorId");
    }
    return jsString(authenticatorId);
}

/**
 * Get the verification ID from the state or from the request.
 */
function getVerificationId() {
    var verificationId = state.get("verificationId");
    if(verificationId == null) {
        verificationId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "verificationId");
    }
    return jsString(verificationId);
}

/**
 * Get the validation ID from the state or from the request.
 */
function getValidationId() {
    var validationId = state.get("validationId");
    if(validationId == null) {
        validationId = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "validationId");
    }
    return jsString(validationId);
}

/**
 * Get the OTP from the state or from the request.
 */
function getOTP() {
    var otp = state.get("otp");
    if(otp == null) {
        otp = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp");
    }
    return jsString(otp);
}

/**
 * Get the action from the state or from the request.
 */
function getAction() {
    var action = state.get("action");
    if(action == null) {
        action = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "action");
    }
    return jsString(action);
}

/**
 * Get the username from the session
 */
function getUsernameFromSession() {
    var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
    return jsString(username);
}

/**
 * Get the username from the state, session, or request.
 */
function getUsername() {
    var username = state.get("username");
    if(username == null) {
        username = getUsernameFromSession();
    }
    if(username == null) {
        username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
    }
    return jsString(username);
}

/**
 * Get the password from the request.
 */
function getPassword() {
    var password = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
    return jsString(password);
}

/**
 * Set the username into the session..
 */
function setUsername(username) {
    var originalUsername = state.get("originalUsername");
    if(originalUsername != null && originalUsername != username) {
        // If we mapped our username, we want to save the unmapped version.
        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", originalUsername);
    } else {
        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
    }
}

/**
 * Get the last validation from the state or from the request.
 */
function getLastValidation() {
    var lastValidation = state.get("lastValidation");
    if(lastValidation == null) {
        lastValidation = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "lastValidation");
    }
    return jsString(lastValidation);
}

/**
 * Get the enabled variable from the request.
 */
function getEnabled() {
    var enabled = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "enabled");
    return jsString(enabled);
}

/**
 * Get the auth status from the session.
 */
function getAuthStatus() {
    var status = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authStatus");
    return jsString(status);
}

/**
 * Set the auth status into the session.
 */
function setAuthStatus(status) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authStatus", status);
}

/**
 * Set the auth type into the session.
 */
function setAuthType(type) {
    // Fetch existing types first.
    var existingTypes = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "ciAuthType");
    if(existingTypes != null) {
        // If we have existing types, and the list doesn't already include our new type,
        // add it.
        if(!existingTypes.includes(type)) {
            var types = [existingTypes, type];
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "ciAuthType", jsString(types));
        }
    } else {
        // No existing types. Add our type.
        context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "ciAuthType", type);
    }
}

/**
 * Get the locale from the request.
 */
function getLocale() {
    var locale = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "Accept-Language");
    return jsString(locale);
}

/**
 * Set the 'enrolling' flag in the state. This is used to keep track of what
 * state a Verify registration is in.
 */
function setIsVerifyEnrolling(isEnrolling) {
    state.put("verifyEnrolling", isEnrolling);
}

/**
 * Get the 'enrolling' flag from the state or session.
 */
function getIsVerifyEnrolling() {
    var isEnrolling = state.get("verifyEnrolling");
    if(isEnrolling == null) {
        isEnrolling = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "enrollment");
    }
    return jsString(isEnrolling);
}

/**
 * Set the 'jitEnrolling' flag in the state. This is used to keep track that we're in a
 * JIT enrollment flow when performing stepup before registration.
 */
function setJITEnrolling(jitEnrolling) {
    state.put("jitEnrolling", jitEnrolling);
}

/**
 * Get the 'jitEnrolling' flag from the state.
 */
function getJITEnrolling() {
    var jitEnrolling = state.get("jitEnrolling");
    return jsString(jitEnrolling);
}

/**
 * Fetch the 'jitEnrolling' flag from the state, and also pull jitType from the request,
 * and store it in state.
 */
function checkIfJITEnrolling() {
    var jitEnrolling = state.get("jitEnrolling");

    var jitType = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "jitType");
    if(jitType != null) {
        state.put("jitType", jitType);
    }

    return jsString(jitEnrolling);
}

/**
 * Clear the JIT enrolling vars from the state.
 */
function clearJITEnrollingState() {
    state.remove("jitEnrolling");
    state.remove("jitType");
}

/**
 * Get the 'jitType' from the state.
 */
function getJITType() {
    var jitType = state.get("jitType");
    return jsString(jitType);
}

/**
 * Get authenticator by ID.
 */
function getAuthenticatorById(id) {
    var authenticator = null;
    var authenticators = JSON.parse(state.get("authenticators"));

    if(authenticators == null || authenticators.length == 0) {
        var resp = CiClientV2.getAuthenticator(conn, id, getLocale());
        var json = getJSON(resp);
        if (resp != null && resp.getCode() == 200 && json != null) {
            authenticator = json;
        }
    } else {
        for(j = 0; j < authenticators.length; j++) {
            if(authenticators[j].id == id) {
                authenticator = authenticators[j];
                break;
            }
        }
    }
    return authenticator;
}

/**
 * Get auth method by ID.
 */
function getAuthMethodById(id) {
    var authMethod = null;
    var authMethods = JSON.parse(state.get("authMethods"));

    if(authMethods == null || authMethods.length == 0) {
        var resp = CiClientV2.getFactors(conn, "userId=\"" + userId + "\"", getLocale());
        var json = getJSON(resp);
        if (resp != null && resp.getCode() == 200 && json != null) {
            authMethods = json.factors;
        }
    }

    if(authMethods != null && authMethods.length > 0) {
        for(j = 0; j < authMethods.length; j++) {
            if(authMethods[j].id == id) {
                authMethod = authMethods[j];
                break;
            }
        }
    }
    return authMethod;
}

/**
 * Get signature method by ID.
 */
function getSignatureMethodById(id) {
    var signatureMethod = null;
    var signatureMethods = JSON.parse(state.get("signatureMethods"));

    if(signatureMethods == null || signatureMethods.length == 0) {
        var resp = CiClientV2.getFactors(conn, "userId=\"" + userId + "\"", getLocale());
        var json = getJSON(resp);
        if (resp != null && resp.getCode() == 200 && json != null) {
            signatureMethods = json.factors.filter(method => {return method.type === "signature" || method.type === "signatures";});
        }
    }

    if(signatureMethods != null && signatureMethods.length > 0) {
        for(j = 0; j < signatureMethods.length; j++) {
            if(signatureMethods[j].id == id) {
                signatureMethod = signatureMethods[j];
                break;
            }
        }
    }
    return signatureMethod;
}

/**
 * Get signature method by ID.
 */
function getTransientMethodById(id, type) {
    var transientMethod = null;

    var resp = CiClientV2.getFactorVerification(conn, type, "transient", id, getLocale());
    var json = getJSON(resp);
    if (resp != null && resp.getCode() == 200 && json != null) {
        transientMethod = json;
    }

    return transientMethod;
}

/**
 * Clean the state! At this point we remove the type, ID, verification ID, last
 * validation, and correlation.
 */
function cleanState() {
    state.remove("type");
    state.remove("id");
    state.remove("verificationId");
    state.remove("lastValidation");
    state.remove("correlation");
    state.remove("authenticatorId");
    state.remove("verifyEnrolling");
}

/**
 * Map the transient type to the basic type name.
 */
function mapTransientType(type) {
    var simpleType = "emailotp";
    if(type == "transientsms") {
        simpleType = "smsotp";
    }
    return simpleType;
}

/**
 * Attempt to parse the response for the JSON body.
 */
function getJSON(resp) {
    var json = null;
    if(resp != null && resp.getBody() != null) {
        try {
            json = JSON.parse(resp.getBody());
        } catch(e) {
            IDMappingExtUtils.traceString("Error response: "+e);
        }
    }
    return json;
}

/**
 * Get the values in the given object as an array.
 */
function objectValues(object) {
    var array = [];
    for (var i in object) {
        if (object.hasOwnProperty(i)) {
            array.push(object[i]);
        }
    }
    return array;
}

/**
 * Take an array of methods and mask any sensitive emails or mobile numbers.
 */
function maskSensitive(array) {
    var newArray = JSON.parse(JSON.stringify(array))

    for(var methodIndex in newArray) {
        for(var key in newArray[methodIndex]) {

            if(key == "transientsms") {
                var mobile = newArray[methodIndex][key];
                newArray[methodIndex][key] = maskPhone(mobile);

            } else if(key == "transientemail") {
                var email = newArray[methodIndex][key];
                newArray[methodIndex][key] = maskEmail(email);

            } else if(key == "attributes") {

                var mobile = newArray[methodIndex][key]["otpDeliveryMobileNumber"];
                if(mobile != null && mobile != "") {
                    newArray[methodIndex][key]["otpDeliveryMobileNumber"] = maskPhone(mobile);
                }

                var email = newArray[methodIndex][key]["otpDeliveryEmailAddress"];
                if(email != null && email != "") {
                    newArray[methodIndex][key]["otpDeliveryEmailAddress"] = maskEmail(email);
                }

                var mobile = newArray[methodIndex][key]["phoneNumber"];
                if(mobile != null && mobile != "") {
                    newArray[methodIndex][key]["phoneNumber"] = maskPhone(mobile);
                }

                var email = newArray[methodIndex][key]["emailAddress"];
                if(email != null && email != "") {
                    newArray[methodIndex][key]["emailAddress"] = maskEmail(email);
                }
            }
        }
    }
    return newArray;
}

/**
 * Prune extra data from the authenticators array.
 */
function pruneAuthenticators(array) {
    var newArray = JSON.parse(JSON.stringify(array))

    for(var methodIndex in newArray) {
        if(newArray[methodIndex]["clientId"]) {
            delete newArray[methodIndex]["clientId"];
        }
        if(newArray[methodIndex]["attributes"]) {
            if(newArray[methodIndex]["attributes"]["pushToken"]) {
                delete newArray[methodIndex]["attributes"]["pushToken"];
            }
            if(newArray[methodIndex]["attributes"]["deviceId"]) {
                delete newArray[methodIndex]["attributes"]["deviceId"];
            }
            if(newArray[methodIndex]["attributes"]["applicationId"]) {
                delete newArray[methodIndex]["attributes"]["applicationId"];
            }
        }
    }
    return newArray;
}

/**
 * Prune extra data from the signatures array.
 */
function pruneSignatureMethods(array) {
    var newArray = JSON.parse(JSON.stringify(array))

    for(var methodIndex in newArray) {
        if(newArray[methodIndex]["_embedded"]) {
            if(newArray[methodIndex]["_embedded"]["clientId"]) {
                delete newArray[methodIndex]["_embedded"]["clientId"];
            }
            if(newArray[methodIndex]["_embedded"]["attributes"]) {
                if(newArray[methodIndex]["_embedded"]["attributes"]["pushToken"]) {
                    delete newArray[methodIndex]["_embedded"]["attributes"]["pushToken"];
                }
                if(newArray[methodIndex]["_embedded"]["attributes"]["deviceId"]) {
                    delete newArray[methodIndex]["_embedded"]["attributes"]["deviceId"];
                }
                if(newArray[methodIndex]["_embedded"]["attributes"]["applicationId"]) {
                    delete newArray[methodIndex]["_embedded"]["attributes"]["applicationId"];
                }
            }
        }
    }

    return newArray;
}

/**
 * Mask the given phone number.
 */
function maskPhone(number) {
    var masked = "";
    for(j = 0; j < number.length; j++) {
        if(number[j] == "+") {
            masked += number[j];
        } else if(j > number.length - 4) {
            masked += number[j];
        } else if(!masked.includes('*')) {
            // Lets not indicate how long the phone number is
            masked += '******';
        }
    }
    return masked;
}

/**
 * Mask the given email.
 */
function maskEmail(email) {
    var masked = "";
    var atIndex = email.length;
    for(j = 0; j < email.length; j++) {
        if(email[j] == "@") {
            atIndex = j;
            masked += email[j];
        } else if(j > atIndex) {
            masked += email[j];
        } else if(j < 3) {
            masked += email[j];
        } else if(!masked.includes('*')) {
            // Lets not indicate how long the email is
            masked += '******';
        }
    }
    return masked;
}

/**
 * Encodes values in the given JS Object. If encodedKeys is not null, only the keys defined
 * are encoded.
 *
 * @param {Object} jsObj the object to encode the values of
 * @param {Array<String>} encodedKeys a subset of keys to encode the values of
 * @returns the encoded object.
 */
function encodeValues(jsObj, encodedKeys) {
    let jsObject = JSON.parse(JSON.stringify(jsObj));
    let keys = Object.keys(jsObject);
    keys.forEach((key) => {
        if(jsObject[key] != null && typeof jsObject[key] == "object") {
            jsObject[key] = encodeValues(jsObject[key], encodedKeys);

        } else if(jsObject[key] != null && (encodedKeys == null || encodedKeys.indexOf(key) > -1)){
            jsObject[key] = jsString(IDMappingExtUtils.escapeHtml(jsObject[key]));
        }
    });
    return jsObject;
}

/**
 * Convert the given java string into a javascript string!
 */
function jsString(javaString) {
    if(javaString != null) {
        javaString = "" + javaString;
    }
    return javaString;
}
