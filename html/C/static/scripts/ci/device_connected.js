// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("submitDone").addEventListener('click', submitDone);
});

var dc_deviceName = document.currentScript.dataset.deviceName;
var dc_type = document.currentScript.dataset.type;

function submitDone() {
    document.getElementById("doneForm").submit();
}

function populateStrings() {
    document.title = ciMsg.ibmVerify;
    document.querySelector('h3').textContent = ciMsg.success;
    if (dc_type == "verify" || dc_type == "totp") {
        document.querySelector('h1').textContent = ciMsg.deviceConnected;
        if (dc_deviceName != null && dc_deviceName != "") {
            document.querySelector('#done-section p').textContent = ciMsg.deviceReady.replace("DEVICE_NAME", dc_deviceName)
        } else {
            document.querySelector('#done-section p').textContent = ciMsg.authenticatorReady;
        }
    } else if (dc_type == "smsotp") {
        document.querySelector('h1').textContent = ciMsg.mobileConnected;
        document.querySelector('#done-section p').textContent = ciMsg.smsReady;
    } else if (dc_type == "emailotp") {
        document.querySelector('h1').textContent = ciMsg.emailConnected;
        document.querySelector('#done-section p').textContent = ciMsg.emailReady;
    }
    document.querySelector("#done-section .button-bottom").textContent = ciMsg.done;
}

function startup() {
    populateStrings();
}
