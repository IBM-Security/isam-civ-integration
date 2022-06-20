window.addEventListener('load', (event) => {
    startup();

    document.getElementById("cancel").addEventListener("click", cancel);
});

var wait_pollTimer = null;

function cancel() {
    if (wait_pollTimer != null) {
        window.clearTimeout(wait_pollTimer);
    }
    document.getElementById("cancelForm").submit();
}

function populateStrings() {
    document.title = ciMsg.ibmVerify;
    document.querySelector('h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('h1').textContent = ciMsg.letsMakeSure;
    document.getElementById("instructions").textContent = ciMsg.verifyInstructions;
}

function startup() {
    populateStrings();

    wait_pollTimer = setTimeout(function() {
        document.getElementById("pollForm").submit();
    }, 2000);
}
