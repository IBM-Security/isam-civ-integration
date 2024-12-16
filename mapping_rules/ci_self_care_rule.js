importPackage(Packages.com.ibm.security.access.ciclient);
importPackage(Packages.com.ibm.security.access.server_connections);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("CI_Common");
importMappingRule("CI_Enrollment_Methods");

/**
 * Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
 *
 * This mapping rule allows a IBM Verify user to add or modify
 * authentication methods.
 *
 * Updates to this file will also be made available at:
 *      https://github.com/IBM-Security/isam-civ-integration
 *
 * At this point, support is fully included for: SMS OTP, Email OTP, and TOTP.
 *
 * The main part of this rule forks into different responses based on the request
 * parameter "action". Supported action values are:
 * null || "initiate": Display the already registered auth methods to the user.
 *         Also display a button to allow users to register more methods.
 * "register": Register/enroll a method based on the given type.
 *         For TOTP, enroll the method and return a QR code.
 *         For SMS and Email OTP, enroll the method and return a validation
 *         if required.
 *         For Verify, initiate the registration and return a QR code.
 * "validateOTP": Validate the OTP provided as a request parameter. In some
 *         cases, the enrollment must be validated before it can be used at
 *         runtime for authentication/verification.
 * "remove": Remove the enrollment with the given ID.
 * "update": Update the enrollment with a given ID. This is mainly used to 
 *         enable or disable an auth method.
 * "pollEnrollment": Poll an in-progress authenticator enrollment to check if it has been
 *         completed successfully yet.
 */

// The types of methods a user is allowed to complete. Only the types included
// in this list will be displayed to the end user as an authentication option.
// Possible values are: "Verify", "SMSOTP", "EmailOTP", "TOTP"
var enabledMethods = ["Verify", "SMSOTP", "EmailOTP", "TOTP"];

IDMappingExtUtils.traceString("Entry CI_Self_Care_Rule");

// The possible error messages returned by this rule.
var errorMessages = {
    "invalid_action"            : macros.get("@INVALID_ACTION@"), // "The action provided was invalid for this mechanism."
    "user_not_found"            : macros.get("@USER_NOT_FOUND_MSG@"), // "User not found."
    "login_failed"              : macros.get("@LOGIN_FAILED@"), // "Login failed. You have used an invalid user name or password."
    "auth_method_get_failed"    : macros.get("@AUTH_METHOD_GET_FAIL_MSG@"), // "Retrieving authentication methods failed."
    "registration_failed"       : macros.get("@REGISTRATION_FAILED_MSG@"), // "Registration failed."
    "registration_failed_colon" : macros.get("@REGISTRATION_FAILED_COLON_MSG@"), // "Registration failed:"
    "validation_failed"         : macros.get("@VALIDATION_FAILED_MSG@"), // "Validation failed."
    "validation_failed_colon"   : macros.get("@VALIDATION_FAILED_COLON_MSG@"), // "Validation failed:"
    "verification_failed"       : macros.get("@VERIFICATION_FAILED_MSG@"), // "Verification failed."
    "verification_failed_colon" : macros.get("@VERIFICATION_FAILED_COLON_MSG@"), // "Verification failed:"
    "update_failed"             : macros.get("@UPDATE_FAILED_MSG@"), // "Update failed."
    "update_failed_colon"       : macros.get("@UPDATE_FAILED_COLON_MSG@"), // "Update failed:"
    "removal_failed"            : macros.get("@REMOVAL_FAILED_MSG@"), // "Removal failed."
    "removal_failed_colon"      : macros.get("@REMOVAL_FAILED_COLON_MSG@"), // "Removal failed:"
    "no_type"                   : macros.get("@NO_TYPE_MSG@"), // "No type provided."
    "no_id"                     : macros.get("@NO_ID_MSG@"), // "No ID provided."
    "no_otp"                    : macros.get("@NO_OTP_MSG@"), // "No OTP provided."
    "no_otp_delivery"           : macros.get("@NO_OTP_DELIVERY_MSG@"), // "No OTP delivery detail provided."
    "no_validation_id"          : macros.get("@NO_VALIDATION_ID_MSG@"), // "No validation ID provided."
    "no_verification_id"        : macros.get("@NO_VERIFICATION_ID_MSG@"), // "No verification ID provided."
    "create_transaction_failed" : macros.get("@CREATE_TRANSACTION_FAILED_MSG@"), // "Could not create transacton."
    "create_validation_failed"  : macros.get("@CREATE_VALIDATION_FAILED_MSG@"), // "Could not create validation."
    "create_verification_failed": macros.get("@CREATE_VERIFICATION_FAILED_MSG@") // "Could not create verification."
}

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

// This fetches the server connection saved against the specific auth mechanism
// for this rule.
var conn = ServerConnectionFactory.getCiConnectionById(macros.get("@SERVER_CONNECTION@"));

// This block does early processing of the enabledMethods variable to determine
// which methods should be shown to the user.
var includeTOTP = enabledMethods.indexOf("TOTP") != -1;
var includeSMS = enabledMethods.indexOf("SMSOTP") != -1;
var includeEmail = enabledMethods.indexOf("EmailOTP") != -1;
var someAuthnMethodsEnabled = includeTOTP || includeSMS || includeEmail;
var allAuthnMethodsEnabled = includeTOTP && includeSMS && includeEmail;

// Get the auth status. This will be set by the auth rule in the case where the
// user has to auth before doing a protected action.
var authStatus = getAuthStatus();

// First step is to authenticate the user against CI with their username and
// password. If no username has been supplied as a request parameter, redirect
// to a page requesting it and the password.
var username = checkLogin();

// If the user just authed with basicAuth, or authed with IVIA, or the user
// just performed a CI auth, you may pass!
if(username != null ||
    (authStatus != null && (authStatus == "success" || authStatus == "read"))) {
    //First try and get the CI user ID from the state map. If not there, do
    // a lookup of CI to get the user ID.
    var userId = getUserId(conn, username);

    // Only continue if we have successfully fetched the user ID.
    if(userId != null) {
        // userId or username might not yet be in javascript string form, so
        // convert them now.
        userId = jsString(userId);
        username = jsString(username);

        var action = getAction();

        // If authStatus has been set, and it was a success, we need to
        // override whatever action has carried over from the Auth rule.
        // Also update authStatus such that it can't be read again.
        if(authStatus != null && authStatus == "success") {
            action = "initiate";
            setAuthStatus("read");
        }
        IDMappingExtUtils.traceString("Action: "+action);

        if(action == null || action == "initiate") {
            // Display the already registered auth methods to the user.
            // Also display a button to allow users to register more methods.

            // First clean the state. cleanState is defined in CI_Common.js
            // Check the function definition to confirm which state 
            // variables are cleared.
            cleanState();
            var methods = [];

            // Only make a request to CI to fetch standard auth methods if at
            // least one of either TOTP, SMS OTP or Email OTP is included
            // in enabledMethods
            if(someAuthnMethodsEnabled) {
                var resp = CiClientV2.getFactors(conn, "userId=\"" + userId + "\"&type!=\"signature\"", getLocale());
                var json = getJSON(resp);
                if (resp != null && resp.getCode() == 200 && json != null) {
                    var allMethods = json.factors;

                    // If all methods are included in enabledMethods, just return
                    // the methods array as-is.
                    if(allAuthnMethodsEnabled) {
                        methods = allMethods;
                    } else {
                        // Otherwise, process the returned methods and only pull
                        // out those that are in enabledMethods.
                        for(j = 0; j < allMethods.length; j++) {
                            var method = allMethods[j];
                            if((method["methodType"] == "totp" || method["type"] == "totp") && includeTOTP) {
                                methods.push(method);
                            }
                            if((method["methodType"] == "smsotp" || method["type"] == "smsotp") && includeSMS) {
                                methods.push(method);
                            }
                            if((method["methodType"] == "emailotp" || method["type"] == "emailotp") && includeEmail) {
                                methods.push(method);
                            }
                        }
                    }
                } else {
                    // The request failed. Return an error page via our handleError
                    // method (defined in CI_Common.js).
                    handleError(errorMessages["auth_method_get_failed"], null);
                }
            }

            // Only make a request to CI to fetch authenticators if Verify
            // is included in enabledMethods
            var authenticators = [];
            if(enabledMethods.indexOf("Verify") != -1) {
                var resp = CiClientV2.getAuthenticators(conn, userId, getLocale());
                var json = getJSON(resp);
                if (resp != null && resp.getCode() == 200 && json != null) {
                    authenticators = json.authenticators;
                } else {
                    // The request failed. Return an error page via our handleError
                    // method (defined in CI_Common.js).
                    handleError(errorMessages["auth_method_get_failed"], null);
                }
            }

            // Now populate all the macros! These macros are how we tell the
            // HTML pages what methods we have available.
            // Also save each method type in the state map.
            macros.put("@AUTH_METHODS@", JSON.stringify(encodeValues(maskSensitive(methods), ["nickname"])));
            macros.put("@METHOD_COUNT@", jsString(methods.length));
            state.put("authMethods", JSON.stringify(methods));

            let encodedAuthenticators = encodeValues(authenticators, ["deviceType", "platformType", "deviceName", "osVersion"]);
            macros.put("@AUTHENTICATORS@", JSON.stringify(pruneAuthenticators(encodedAuthenticators)));
            macros.put("@DEVICE_COUNT@", jsString(authenticators.length));
            state.put("authenticators", JSON.stringify(authenticators));

            macros.put("@ENABLED_METHODS@", JSON.stringify(enabledMethods));
            macros.put("@USERNAME@", username);
            page.setValue("/authsvc/authenticator/ci/usc.html");

            // Log all the methods we fetched.
            IDMappingExtUtils.traceString("CI authentication methods: "+JSON.stringify(methods));
            IDMappingExtUtils.traceString("CI authenticators: "+JSON.stringify(authenticators));
        }
        else if(action == "register") {
            // The user has chosen to register a method or authenticator.
            // Let's process it depending on the method type.
            var type = getType();
            state.put("type", type);

            // If the type is verify, this is a IBM Verify authenticator
            // registration.
            if(type == "verify") {
                enrollVerify(conn, userId, username);

            } else if(type == "emailotp" || type == "smsotp") {
                enrollEmailOrSMS(conn, type, userId, username);

            } else if(type == "totp") {
                enrollTOTP(conn, userId, username);

            } else {
                handleError(errorMessages["registration_failed_colon"] + " " + errorMessages["no_type"], null);
                // Clean the state. cleanState is defined in CI_Common.js
                // Check the function definition to confirm which state variables
                // are cleared.
                cleanState();
            }
        }
        else if(action == "validateOTP") {
            validateOTP(conn);
        }
        else if(action == "remove") {
            // Remove the method/authenticator with the given ID. The user
            // also has to chose the type in the request.
            var type = getType();
            var id = getId();

            if(id != null) {
                if(type == "verify") {
                    // Check method ownership.
                    var authenticator = getAuthenticatorById(id);
                    // Authenticators still use owner
                    if(authenticator != null && authenticator.owner == userId) {

                        // If type is verify, delete the authenticator.
                        var resp = CiClientV2.deleteAuthenticator(conn, id, getLocale());
                        if (resp != null && resp.getCode() == 204) {
                            // Return a status payload with success.
                            macros.put("@STATUS@", "success");
                            page.setValue("/authsvc/authenticator/ci/status.html");
                            // Clean the state. cleanState is defined in CI_Common.js
                            // Check the function definition to confirm which state variables
                            // are cleared.
                            cleanState();
                        } else {
                            // The request failed. Return an error page via our
                            // handleError method (defined in CI_Common.js).
                            handleError(errorMessages["removal_failed"], resp);
                        }
                    } else {
                        // Authenticated user does not match authenticator owner. Return
                        // an error page.
                        handleError(errorMessages["removal_failed"], null);
                    }
                } else if(type == "smsotp" || type == "emailotp" || type == "totp") {
                    // If type is anything else, delete the method.

                    // Check method ownership.
                    var authMethod = getAuthMethodById(id);
                    if(authMethod != null && authMethod.userId == userId) {
                        var resp = CiClientV2.deleteFactor(conn, type, id, getLocale());
                        if (resp != null && resp.getCode() == 204) {
                            // Return a status payload with success.
                            macros.put("@STATUS@", "success");
                            page.setValue("/authsvc/authenticator/ci/status.html");
                            // Clean the state. cleanState is defined in CI_Common.js
                            // Check the function definition to confirm which state variables
                            // are cleared.
                            cleanState();
                        } else {
                            // The request failed. Return an error page via our
                            // handleError method (defined in CI_Common.js).
                            handleError(errorMessages["removal_failed"], resp);
                        }
                    } else {
                        // Authenticated user does not match auth method owner. Return
                        // an error page.
                        handleError(errorMessages["removal_failed"], null);
                    }
                } else {
                    // No type was supplied. Return an error page via our
                    // handleError method (defined in CI_Common.js).
                    handleError(errorMessages["removal_failed_colon"] + " " + errorMessages["no_type"], null);
                }
            } else {
                // No ID was supplied. Return an error page via our
                // handleError method (defined in CI_Common.js).
                handleError(errorMessages["removal_failed_colon"] + " " + errorMessages["no_id"], null);
            }
        }
        else if(action == "update") {
            // Update the authenticator with the given ID. The user also has
            // to chose the type in the request. But we only support
            // authenticator updates for now.
            var type = getType();
            var id = getId();
            var enabled = getEnabled();

            if(id != null) {
                if(type == "verify") {
                    // Check method ownership.
                    var authenticator = getAuthenticatorById(id);
                    if(authenticator != null && authenticator.owner == userId) {

                        authenticator.enabled = enabled;

                        var resp = CiClientV2.updateAuthenticator(conn, id, JSON.stringify(authenticator), getLocale());
                        if (resp != null && resp.getCode() == 204) {
                            // Clean the state. cleanState is defined in CI_Common.js
                            // Check the function definition to confirm which state variables
                            // are cleared.
                            cleanState();
                        } else {
                            // The request failed. Return an error page via our
                            // handleError method (defined in CI_Common.js).
                            handleError(errorMessages["update_failed"], resp);
                        }
                    } else {
                        // Authenticated user does not match authenticator owner. Return
                        // an error page.
                        handleError(errorMessages["update_failed"], null);
                    }
                } else {
                    // No type was supplied. Return an error page via our
                    // handleError method (defined in CI_Common.js).
                    handleError(errorMessages["update_failed_colon"] + " " + errorMessages["no_type"], null);
                }
            } else {
                // No ID was supplied. Return an error page via our
                // handleError method (defined in CI_Common.js).
                handleError(errorMessages["update_failed_colon"] + " " + errorMessages["no_id"], null);
            }
        }
        else if(action == "pollEnrollment") {
            pollEnrollment(conn, userId);
        } else {
            // We got another action that wasn't one of our expected ones.
            // Return an error.
            handleError(errorMessages["invalid_action"], null);
        }
    }
}


// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit CI_Self_Care_Rule");
