importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

function utf8decode(value) {
    if (value == null || value.length == 0) return "";
    return decodeURIComponent(escape(value));
}

function buildErrorString(errors, missing) {
    var errorString = "";

    if (missing.length != 0) {
        errorString += "Missing required field(s): "+missing;
    }

    if (errorString != "") errorString += " ";
    if (errors.length != 0) errorString += "Error:";
    for (var error in errors) {
        errorString += " " + errors[error];
    }
    return errorString;
}

function deepcopy(obj) {
    if (null == obj || "object" != typeof obj) return obj;
    var copy = obj.constructor();
    for (var attr in obj) {
        if (obj.hasOwnProperty(attr) && "object" != typeof obj[attr]) copy[attr] = obj[attr];
        if (obj.hasOwnProperty(attr) && "object" == typeof obj[attr]) copy[attr] = deepcopy(obj[attr]);
    }
    return copy;
}

// scimConfig is needed for pretty much all USC mapping rules.
var scimConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "scimConfig");