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
