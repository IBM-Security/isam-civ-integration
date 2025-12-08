importClass(Packages.com.tivoli.am.fim.fido.mediation.FIDO2RegistrationHelper);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.


/* Some mediator demos */

// Set to true to limit the number of registered devices to 5. Checked on an attestation options call.
var is_limit_registrations = false;

// Set to true to save an example attribute on an attestation result call.
var save_example_attribute = false;

// Set to true to return an attribute (user provided frieldy name) on attestation result call.
var return_example_attribute = false;

// Set to true to return an error telling the user they need to register an authenticator if they have none.
var return_needs_register_error = false;

// Set to true to return all additional attributes to the browser on an assertion result call
var return_all_attributes = false;

// Require user verification to be performed during authentication only when user verification was performed at registration
var assert_uv_when_registered = false;

// Set to true to control the client and authenticator authenticator extensions supported by the Relying Party
var enforce_extension_allow_list = false;

// Set to true to mediate attestation options to request the "credPortect" extension if requesting a resident key.
var mediate_attestation_extensions = false;

// Set to true to increase the AUTHENTICATION_LEVEL of a user if a assertion is completed with a resident key and user verification
var modify_authentication_level = false;

// Set to true to enable mediation of registrations based on credProps extension
var cred_props_extension_attributes = false;

// Set to true to enforce resident key creation for new registrations. This will modify options to require a resident
// key and reject registrations which do not indicate that a resident key has been created and user verification performed
var enforce_rk_and_uv = false;

/****************** Rule Helpers****************/
/*
 * Log a message to trace.log.
 *
 * Requires the trace component com.tivoli.am.fim.trustserver.sts.utilities.*=ALL to be enabled
 */
function trace(message) {
    IDMappingExtUtils.traceString("FIDO Mediation: " + message);
}

/*
 * Return an error to the FIDO client.
 */
function return_error(status, message) {
    error.put("status", status);
    error.put("message", message);
}

function associate_attribute(attribute_name, attribute_value) {
    if (context.requestType != "attestation_result") {
        trace("Cannot save attributes on request type " + context.requestType);
    } else {
        attributes.put(attribute_name, attribute_value);
    }
}

function get_attribute(attribute_name) {
    if (context.requestType != "attesation_result" && context.requestType != "assertion_result") {
        trace("Cannot retrieve attributes on request type " + context.requestType);
    }
    result = context.requestData.registration.attributes[attribute_name];
    if (result == null) {
        result = attributes.get(attribute_name);
    }
    return result;
}


/****************** Primary methods ****************/


/*
 * Mediate an attestation options call. With this method you can:
 * - return an error if the requested options are not allowed
 *
 * For example, you could return an error if a user is only allowed to register 5 authenticators and they are at the limit.
 */
function mediate_attestation_options() {

    if (is_limit_registrations) {
        var helper = new FIDO2RegistrationHelper();
        var username = stsuu.getPrincipalName();
        var registrations = helper.getRegistrationsByUsername(username);
        if (registrations.size() >= 5) {
            return_error("too_many_devices", "You cannot register that many registrations.");
        }
    }

    if (mediate_attestation_extensions) {
        var authenticatorSelection = attestation_options.get("authenticatorSelection");
        if (authenticatorSelection != null && authenticatorSelection.get("requireResidentKey") == true) {
            attestation_options.put("extensions", {"credentialProtectionPolicy": "userVerificationRequired"});
            authenticatorSelection.put("userVerification", "required");
        }
    }

    if (enforce_rk_and_uv) {
        // This demo code will mediate all attestation options calls to require a resident key using L2
        // specifications. It will also remove the depreciated L1 specification for requesting a resident key.
        var authenticatorSelection = attestation_options.get("authenticatorSelection");
        authenticatorSelection.put("residentKey", "required");
        authenticatorSelection.remove("requireResidentKey");
    }
}

/*
 * Mediate an attestation result call. With this method you can:
 * - save attributes
 * - return additional response data/credential data
 * - return an error if this registration should not be successful
 */
function mediate_attestation_result() {
    if (save_example_attribute) {
        associate_attribute("exampleAttribute", "exampleValue");
    }

    if (return_example_attribute) {
        //To view avaliable fields which could be returned to the user use 'trace(JSON.stringify(context.requestData))'
        responseData.put('Credential Identifier', context.requestData.registration.credentialId)
        responseData.put('Friendly Name', context.requestData.registration.friendlyName)
    }

    if (cred_props_extension_attributes) {
        //This demo code will check for the presence of the credProps extension. If avaliable it will create an 
        //attribute to store with the registration, hinting whether the client created a resident key.
        var extensions = context.requestData.extensions;
        if (('credProps' in extensions) && ('rk' in extensions.credProps)) {
            //Extension is avaliable to create attributes
            associate_attribute("residentKey", ''+extensions.credProps.rk);
        }
    }

    if (enforce_rk_and_uv) {
        // This demo code will reject registrations which do not indicate that a resident key was created
        // or user verification was performed (requirement of resident keys)
        var extensions = context.requestData.extensions;
        if (('credProps' in extensions) && ('rk' in extensions.credProps)) {
            if (extensions.credProps.rk != true) {
                return_error("resdent_key_required", "Client must indicate that a resident key was created using the credProps extension");
            }
        } else {
            return_error("cred_props_extension_missing", "Client either: did not include the credProps extension; or did not include the rk field, which is required for this scenario");
        }
        if (!context.requestData.authData.uv) {
            return_error("user_verification_required", "User verification must be performed when creating this registration.");
        }
    }
}

/*
 * Mediate an assertion options call.
 * With this method you can:
 *  - return an error if this authentication should not be successful
 */
function mediate_assertion_options() {
    if (return_needs_register_error) {
        var helper = new FIDO2RegistrationHelper();
        var username = stsuu.getPrincipalName();
        var registrations = helper.getRegistrationsByUsername(username);
        if (registrations.isEmpty()) {
            return_error("no_registered_devices", "You need to register an registration before you can authenticate.");
        }
    }
}

/*
 * Mediate an assertion result call.
 * With this method you can:
 *  - access registration attributes
 *  - return additional response data/credential data
 *  - return an error if this authentication should not be successful
 */
function mediate_assertion_result() {

    if(assert_uv_when_registered && context.requestData.registration.userVerified && !context.requestData.authData.uv) {
        return_error("UV_REQUIRED", "User verification must be performed when authenticating with this registration.");
    }

    if (return_all_attributes) {
        for (var i in context.requestData.registration.attributes) {
            responseData.put(i, context.requestData.registration.attributes[i])
        }
    }

    if (modify_authentication_level) {
        var userVerification = context.requestData.authData.uv && context.requestData.registration.userVerified;
        if (userVerification == true) {
            credentialData.put("AUTHENTICATION_LEVEL", "2");
        }
    }

    if (cred_props_extension_attributes) {
        //This demo ode will fail any assertion which was created with a resdent key (indicated by an attribute stored
        //with the registration) and user verification was not performed.
        var resident_key = get_attribute("residentKey");
        if (resident_key != undefined) {
            if(resident_key == "true" && context.requestData.authData.uv == false) {
                return_error("UV_REQUIRED", "Credential was creaded with a resident key. User Verification must be performed");
            }
        }
    }
}

/*
 * Mediate attestation extensions.
 * With this method you can control which extensions are accepted by the relying party
 * during attestation ceremonies.
 * If an extension is returned by the client or authenticator which is not allowed, the
 * registration is rejected and the invalid extension is returned to the user
 *
 */
function mediate_attestation_extensions() {
    var allowedClientExtensions =  ["credProps"];
    var allowedAuthenticatorExtensions =["credProtect"];
    var authenticatorExtensions = context.requestData.attestationObject.authData.extensions;
    var clientExtensions = context.requestData.extensions;
    if (clientExtensions) {
        for (var ext in clientExtensions) {
            if (allowedClientExtensions.indexOf(ext) < 0) {
                return_error("INVALID EXTENSIONS", "Recieved a client extension [" + JSON.stringify(ext) + "] which is not allowed");
             }
         }
    }
    if (authenticatorExtensions) {
        for (ext in authenticatorExtensions) {
            if (allowedAuthenticatorExtensions.indexOf(ext) < 0) {
                return_error("INVALID EXTENSIONS", "Recieved a authenticator extension [" + JSON.stringify(ext) + "] which is not allowed");
            }
        }
    }
}

/*
 * Mediate assertion extensions
 * With this method you can control which extensions are accepted by the relying party
 * during assertion ceremonies.
 * If an extension is returned by the client or authenticator which is not allowed, the
 * assertion is rejected and the invalid extension is returned to the user
 *
 */
function mediate_assertion_extensions() {
    var allowedExtensions = ["appid"];
    var authenticatorExtensions = context.requestData.authData.extensions;
    var clientExtensions = context.requestData.extensions;
    if (clientExtensions) {
        for (var ext in clientExtensions) {
            if (allowedExtensions.indexOf(ext) < 0) {
                return_error("INVALID EXTENSIONS", "Recieved a client extension [" + JSON.stringify(ext) + "] which is not allowed");
             }
         }
    }
    if (authenticatorExtensions) {
        for (ext in authenticatorExtensions) {
            if (allowedExtensions.indexOf(ext) < 0) {
                return_error("INVALID EXTENSIONS", "Recieved a authenticator extension [" + JSON.stringify(ext) + "] which is not allowed");
            }
        }
    }
}

/*********************
 * Main rule processing.
 *********************/

if (context.requestType == "attestation_options") {
    mediate_attestation_options();
} else if (context.requestType == "attestation_result") {
    mediate_attestation_result();
    if (enforce_extension_allow_list) {
        mediate_attestation_extensions();
    }

} else if (context.requestType == "assertion_options") {
    mediate_assertion_options();
} else if (context.requestType == "assertion_result") {
    mediate_assertion_result();
    if (enforce_extension_allow_list) {
        mediate_assertion_extensions();
    }

} else {
    trace("Something has gone wrong.");
}
