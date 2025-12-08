importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.tivoli.am.fim.registrations);
importPackage(Packages.com.ibm.security.access.user);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

/**
 * Get the branches of this decision from the BRANCHES macro.
 */
function getBranches() {
    return JSON.parse(macros.get("@BRANCHES@"));
}

/**
 * Build a list of mechanisms included in this decision, and build a map of mechanism to
 * branch name.
 */
function getMechanismsAndBranchMap() {

    var mechanisms = [];
    var branchMap = {};

    var branches = getBranches();
    for(branch in branches) {

        var branchName = branches[branch]["name"];

        var steps = branches[branch]["steps"];
        for(stepIndex in steps) {
            var step = steps[stepIndex];

            // This is the first step in a branch. Add the step to the policy array.
            if(step["id"] == "step1") {
                mechanisms.push(jsString(step["mechanism"]));

                // Also add the mechanism to the branch map.
                branchMap[step["mechanism"]] = jsString(branchName);
            }
        }
    }

    return [mechanisms, branchMap];
}

/**
 * Fetch the user's enrolled methods. If mechanisms is supplied, filter out the methods and
 * return only those in the list.
 */
function getUserData(username, mechanisms) {

    var methods = [];
    var mechMap = {};
    var enrolledMethods = MechanismRegistrationHelper.getRegistrationsForUser(username, getLocale());

    for(i = 0; i < enrolledMethods.size(); i++) {
        var method = enrolledMethods.get(i);
        var uri = method.getMechURI();

        mechMap[uri] = uri.substring(uri.lastIndexOf(":") + 1);

        var add = false;
        if(mechanisms != null) {
            if(JSON.stringify(mechanisms).includes("\"" + uri + "\"")) {
                add = true;
            }
        } else {
            add = true;
        }

        if(add) {
            methods.push(JSON.parse(method.toString()));
        }
    };

    return [methods, mechMap];
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

/**
 * Get the username from the session
 */
function getUsernameFromSession() {
    var username = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
    return jsString(username);
}

/**
 * Get the username from the request.
 */
function getUsername() {
    var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
    return jsString(username);
}

/**
 * Get the password from the request.
 */
function getPassword() {
    var password = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
    return jsString(password);
}

function checkLogin() {
    var sessionUsername = getUsernameFromSession();
    var username = getUsername();

    // If we have the username from the session, return immediately.
    if(sessionUsername != null) {
        return sessionUsername;
    }

    // If we don't have the username from the request, return a login page.
    if(username == null) {
        page.setValue("/authsvc/authenticator/login.html");
        macros.put("@ERROR_MESSAGE@", "user_not_found");
        return null;
    }

    // We've been given the username. Check if username/password auth has already
    // been done successfully for this session by fetching basicAuth from the
    // state map.
    var password = getPassword();

    if(password != null) {
        // If we were given the password as well, attempt auth.
        var isAuthenticated = false;
        try {
            var userLookupHelper = new UserLookupHelper();
            // Try logging in with the Username Password mechanism.
            userLookupHelper.init(true);
            if(userLookupHelper.isReady()) {
                var user = userLookupHelper.getUser(username);
                if(user != null) {
                    isAuthenticated = user.authenticate(password);
                }
            } else {
                macros.put("@ERROR_MESSAGE@", "username_password_mech_not_configured");
                page.setValue("/authsvc/authenticator/error.html");
                return null;
            }
        } catch (ex) {
            macros.put("@ERROR_MESSAGE@", "login_failed");
            page.setValue("/authsvc/authenticator/error.html");
            return null;
        }

        if (isAuthenticated) {
            context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
            IDMappingExtUtils.traceString("User login successful.");
            return username;
        } else {
            macros.put("@ERROR_MESSAGE@", "login_failed");
            page.setValue("/authsvc/authenticator/error.html");
            return null;
        }

    } else if(username != null) {
        IDMappingExtUtils.traceString("Username provided, but no password");
        // We have a username but no password. Return a login page.
        macros.put("@USERNAME@", username);
        page.setValue("/authsvc/authenticator/login.html");
        return null;
    }
}

/**
 * Get the locale from the request.
 */
function getLocale() {
    var locale = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "Accept-Language");
    if(locale != null) {
        return jsString(locale);
    } else {
        // Default to english
        return "en";
    }
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