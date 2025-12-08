// Copyright contributors to the IBM Verify Identity Access AAC Mapping Rules project.

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("BranchingHelper");

IDMappingExtUtils.traceString("Entry Branching MMFA Post Result");

var result = false;

var branchNames = [];
var branches = getBranches();
var username = getUsernameFromSession();

for(key in branches) {
    branchNames.push(branches[key]["name"]);
}
IDMappingExtUtils.traceString("Branch options to be sent to user: " + JSON.stringify(branchNames));

// Get the result of the MMFA verification step
var status = context.get(Scope.SESSION, "urn:ibm:security:asf:mmfa", "mmfa_transaction_status");

IDMappingExtUtils.traceString("STATUS : " + status);

// Hit the correct branch based upon the MMFA result
if(status != null && status != "") {
    var branch = "";

    if(status == "success") {
        branch = "Success";
    } else if(status == "canceled") {
        branch = "Cancel";
    } else if(status == "fail") {
        branch = "Fail";
    } else if(status == "abort") {
        branch = "Abort";
    } else {
        // pending state does not need handling
        IDMappingExtUtils.traceString("Nothing to do with status : " + status);
        result = true;
    }

    if(branch != null && branch != "") {
        state.put("decision", branch);
        IDMappingExtUtils.traceString("Setting decison to branch: "+branch);
        result = true;
    }

} else {
    IDMappingExtUtils.traceString("No status was found.");
    result = false;
}

success.setValue(result);
IDMappingExtUtils.traceString("Exit Branching MMFA Post Result");
