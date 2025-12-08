importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.user);

importMappingRule("BranchingHelper");

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

IDMappingExtUtils.traceString("Entry Branching Second Factor");

var mechanismPriority = ["urn:ibm:security:authentication:asf:mechanism:fido2", "urn:ibm:security:authentication:asf:mechanism:mmfa", "urn:ibm:security:authentication:asf:mechanism:totp", "urn:ibm:security:authentication:asf:mechanism:hotp"];

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

var branchMap = {};
var mechMap = {};
var methods = []
var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();

var username = checkLogin();

// If the user just authed with basicAuth, or authed with IVIA, or the user
// just performed a CI auth, you may pass!
if(username != null) {

    [methods, mechMap] = getUserData(username, mechanisms);

    methods = methods.filter(function(method, index, arr){
        return method["mechanismURI"] != "urn:ibm:security:authentication:asf:mechanism:eula";
    });

    if(methods.length == 0) {
        IDMappingExtUtils.traceString("No enrollments. Throw an error.");
        macros.put("@ERROR_MESSAGE@", "no_second_factor");
        page.setValue("/authsvc/authenticator/error.html");
    } else {

        methods.sort(function(a, b){
            return mechanismPriority.indexOf(a["mechanismURI"]) > mechanismPriority.indexOf(b["mechanismURI"]);
        });
        methods = encodeValues(methods, ["nickname", "deviceName", "deviceType", "osVersion"]);

        macros.put("@METHODS@", JSON.stringify(methods));
        macros.put("@MECHANISMS@", JSON.stringify(mechanisms));
        macros.put("@SECOND_FACTOR_ENROLLMENTS@", JSON.stringify(methods));

        var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");

        IDMappingExtUtils.traceString("Chosen type from request: "+type);

        if(type) {
            for(mech in mechMap) {

                if(mechMap[mech] == type) {
                    IDMappingExtUtils.traceString("Mechanism from type: "+mech);
                    IDMappingExtUtils.traceString("Setting decison to branch: "+branchMap[mech]);

                    state.put("decision", branchMap[mech]);
                    result = true;
                    break;
                }
            }
            if(!result) {
                // Branch choice was provided in request but branch was not found and/or user not enrolled.
                // Return an error message but don't halt the policy. Let the user re-choose.
                IDMappingExtUtils.traceString("Invalid branch. Either user not enrolled or branch does not exist.");
                macros.put("@ERROR_MESSAGE@", macros.get("@INVALID_BRANCH@"));
            }
        }

        page.setValue("/authsvc/authenticator/branching/second_factor_decision.html");
    }
}

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit Branching Second Factor");
