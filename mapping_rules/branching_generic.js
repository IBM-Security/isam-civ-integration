importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

importMappingRule("BranchingHelper");

IDMappingExtUtils.traceString("Entry Branching Generic");

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

var branchNames = [];
var branches = getBranches();
var username = getUsernameFromSession();

for(key in branches) {
    branchNames.push(branches[key]["name"]);
}
IDMappingExtUtils.traceString("Branch options to be sent to user: "+JSON.stringify(branchNames));

macros.put("@BRANCHES@", JSON.stringify(branchNames));

var branch = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "branch");

IDMappingExtUtils.traceString("Chosen branch from request: "+branch);

if(branch) {
    branch = decodeURI(branch);
    IDMappingExtUtils.traceString("Setting decison to branch: "+branch);

    state.put("decision", branch);
    result = true;
}

page.setValue("/authsvc/authenticator/branching/generic_decision.html");

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(result);
IDMappingExtUtils.traceString("Exit Branching Generic");
