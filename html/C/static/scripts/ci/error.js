// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    populateStrings();
    document.getElementById("cancelButton").addEventListener('click', cancel);

});

function cancel() {
    document.getElementById("cancelForm").submit();
}

function populateStrings() {
    document.title = ciMsg.errorLabel;
    document.querySelector("h1").textContent = ciMsg.errorLabel;
}
