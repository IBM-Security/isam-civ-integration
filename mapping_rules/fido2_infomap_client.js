/*********************************************************************
 * Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.
 *
 *   Licensed Materials - Property of IBM
 *   (C) Copyright IBM Corp. 2019. All Rights Reserved
 *
 *   US Government Users Restricted Rights - Use, duplication, or
 *   disclosure restricted by GSA ADP Schedule Contract with
 *   IBM Corp.
 *********************************************************************/

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
var rc = false;

// Change this to the ID if your Relying Party
fido_client = fido2ClientManager.getClient("www.myidp.ibm.com");

function requestParam(key) {
    var value = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", key);
    return (value == null) ? null : ''+value;
}


// Fuction retreives a mutli-value attribute from a request and 
// converts it to a string which can be parsed by JSON.parse
function requestParams(key) {
    var value = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameters", key);
    if(value.length == 1 && value[0].includes('[')) {
        // Already an array, shortcut now.
        return value[0];
    }
    var valueJson = '';
    if(value != null) {
        valueJson = '['
        for(var i = 0; i < value.length; i++) {
            if(i < (value.length - 1)) {
                valueJson += '"' + value[i] + '",';
            } else {
                valueJson += '"' + value[i] + '"]';
            }
        }
    }
    return (value == null) ? null : valueJson;
}


// We expect the parameter fidoInfoMap in the request with a value of
// attestationOptions, attestationResult, assertionOptions or assertionResult
var fidoInfoMap = requestParam("fidoInfoMap");

if (fidoInfoMap == "attestationOptions") {
    var options = JSON.parse(fido_client.attestationOptions("{}"));
    IDMappingExtUtils.traceString(JSON.stringify(options));
    var status = options['status'];
    if (status == 'ok') {
        macros.put("@FIDO_RP_ID@", options['rp']['id']);
        macros.put("@FIDO_RP_NAME@", options['rp']['name']);
        macros.put("@FIDO_TIMEOUT@", options['timeout'].toString());
        macros.put("@FIDO_CHALLENGE@", options['challenge']);
        macros.put('@FIDO_EXTENSIONS@', JSON.stringify(options['extensions']));
        var authenticatorSelection = options['authenticatorSelection']
        if (authenticatorSelection != null) {
            macros.put("@FIDO_AUTHENTICATOR_SELECTION@", JSON.stringify(authenticatorSelection));
        }
        var attestation = options['attestation']
        if (attestation != null) {
            macros.put("@FIDO_ATTESTATION@", attestation);
        }
        macros.put("@FIDO_USER_ID@", options['user']['id']);
        macros.put("@FIDO_USER_NAME@", options['user']['name']);
        macros.put("@FIDO_USER_DISPLAY_NAME@", options['user']['displayName']);
        macros.put("@FIDO_STATUS@", options['status']);
        macros.put("@FIDO_ERROR_MESSAGE@", options['errorMessage']);
        var pubKeyCredParams = options['pubKeyCredParams'];
        macros.put("@FIDO_PUBKEY_CRED_PARAMS@", JSON.stringify( pubKeyCredParams));
        var excludeCredentials = options['excludeCredentials'];
        macros.put("@FIDO_EXCLUDED_CREDENTIALS@", JSON.stringify( excludeCredentials));
        macros.put("@FIDO_INFOMAP_PARAM@", "&fidoInfoMap=attestationResult");
        macros.put("@FIDO_AAGUID_LOOKUP@", fido_client.getAaguidLookupTable());
        page.setValue('/authsvc/authenticator/infomap/fido_attestation.html');
    } else {
        macros.put("@ERROR_MESSAGE@", options['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }

}
else if (fidoInfoMap == "attestationResult") {
    var attestation = {
                    'type': requestParam("type"),
                    'id': requestParam("id"),
                    'rawId': requestParam("rawId"),
                    'response': {
                        'clientDataJSON': requestParam("clientDataJSON"),
                        'attestationObject': requestParam("attestationObject")
                    },
    };
    var clientExtensionResults = requestParam("getClientExtensionResults");
    if (clientExtensionResults != null) {
        attestation['getClientExtensionResults'] = JSON.parse(clientExtensionResults);
    }

    var transports = requestParams("getTransports");
    if(transports != null) {
        attestation['getTransports'] = JSON.parse(transports);
    }

    IDMappingExtUtils.traceString("attestation: " + JSON.stringify(attestation));
    var result = JSON.parse(fido_client.attestationResult( JSON.stringify(attestation)));
    var status = result['status'];
    if (status == 'ok') {
        rc= true;

    } else {
        macros.put( "@ERROR_MESSAGE@", result['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }
    

}
else if (fidoInfoMap == "assertionOptions") {
    var options = JSON.parse(fido_client.assertionOptions("{}"));
    IDMappingExtUtils.traceString(JSON.stringify(options));
    var status = options['status'];
    if (status == 'ok') {
        macros.put("@FIDO_RP_ID@", options['rpId']);
        macros.put("@FIDO_TIMEOUT@", options['timeout'].toString());
        macros.put("@FIDO_CHALLENGE@", options['challenge']);
        macros.put('@FIDO_EXTENSIONS@', JSON.stringify(options['extensions']));
        macros.put("@FIDO_USER_ID@", options['userId'] == null ? "" : options['userId']);
        macros.put("@FIDO_STATUS@", options['status']);
        macros.put("@FIDO_ERROR_MESSAGE@", options['errorMessage']);
        macros.put("@FIDO_ALLOW_CREDENTIALS@", options['allowCredentials'] == null ? "[]" : JSON.stringify(options['allowCredentials']));
        macros.put("@FIDO_INFOMAP_PARAM@", "&fidoInfoMap=assertionResult");
        macros.put("@FIDO_AAGUID_LOOKUP@", fido_client.getAaguidLookupTable());
        page.setValue('/authsvc/authenticator/infomap/fido_assertion.html');
    } else {
        macros.put("@ERROR_MESSAGE@", options['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }
}
else if (fidoInfoMap == "assertionResult") {
    var assertion = {
                    'type': requestParam("type"),
                    'id': requestParam("id"),
                    'rawId': requestParam("rawId"),
                    'response': {
                        'clientDataJSON': requestParam("clientDataJSON"),
                        'authenticatorData': requestParam("authenticatorData"),
                        'signature': requestParam("signature"),
                        'userHandle': requestParam("userHandle")
                    },
    };
    var clientExtensionResults = requestParam("getClientExtensionResults");
    if (clientExtensionResults != null) {
        assertion['getClientExtensionResults'] = JSON.parse(clientExtensionResults);
    }
    IDMappingExtUtils.traceString("assertion: " + JSON.stringify(assertion));
    var result = JSON.parse(fido_client.assertionResult(JSON.stringify(assertion)));
    var status = result['status'];
    if (status == 'ok') {
        rc= true;

    } else {
        macros.put("@ERROR_MESSAGE@", result['errorMessage']);
        page.setValue('/authsvc/authenticator/fido/error.html');
    }

} else {
    macros.put("@ERROR_MESSAGE@", 'expected parameter "fidoInfoMap" in request');
    page.setValue('/authsvc/authenticator/fido/error.html'); 
}

success.setValue(rc);
