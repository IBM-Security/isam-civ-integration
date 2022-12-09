// Copyright contributors to the IBM Security Verify Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("button-1").addEventListener("click", submitDone);
});
var try_push_deviceName = document.currentScript.dataset.deviceName;

function submitDone() {
    document.getElementById("doneForm").action = actionLocation.replace("apiauthsvc", "authsvc");
    document.getElementById("doneForm").submit();
}

var pollCount = 30;
var action = document.currentScript.dataset.action;
var actionLocation = "";

function poll() {
    if (pollCount > 0) {
        var data = {
            "action": "poll"
        };
        var pollRequest = new XMLHttpRequest();
        pollRequest.onreadystatechange = function() {
            processPollRequest(pollRequest);
        };
        pollRequest.open("PUT", actionLocation, true);
        pollRequest.setRequestHeader("Accept", "application/json");
        pollRequest.setRequestHeader("Content-Type", "application/json");
        pollRequest.send(JSON.stringify(data));
        pollCount--;
    }
}

function processPollRequest(request) {
    if (request.readyState == 4) {
        var json = null;
        if (request.responseText) {
            try {
                json = JSON.parse(request.responseText);
            } catch (e) {
                // probably not JSON -- handle in else.
            }
        }
        if (request.status == 200 && json != null) {
            if (json.location != null && json.location != "") {
                actionLocation = json.location;
            }
            if (json.status == "success") {
                showDone();
            } else if (json.status == "pending") {
                setTimeout(poll, 2000);
            } else {
                // We most likely got an error when trying to poll.
                // Stop polling by setting pollCount to 0.
                pollCount = 0;
            }
        } else {
            // We most likely got an error when trying to poll.
            // Stop polling by setting pollCount to 0.
            pollCount = 0;
            if (json != null && json.location != null && json.location != "") {
                actionLocation = json.location;
            }
        }
    }
}

function showDone() {
    document.getElementById("try-section").classList.remove('dialog-content--visible');
    document.getElementById("try-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("try-section").style.left = '-100%';
    }, 300);
    document.getElementById("done-section").style.left = '';
    document.getElementById("done-section").classList.add('dialog-content--visible');
}

function populateStrings() {
    document.title = ciMsg.ibmVerify;
    document.querySelector('#try-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#try-section h1').textContent = ciMsg.letsTry;
    document.querySelector('#try-section p').textContent = ciMsg.notificationSent.replace("DEVICE_NAME", try_push_deviceName);
    document.querySelector('#done-section h3').textContent = ciMsg.success;
    document.querySelector('#done-section h1').textContent = ciMsg.deviceConnected;
    if (try_push_deviceName != null && try_push_deviceName != "") {
        document.querySelector('#done-section p').textContent = ciMsg.deviceReady.replace("DEVICE_NAME", try_push_deviceName)
    } else {
        document.querySelector('#done-section p').textContent = ciMsg.authenticatorReady;
    }
    document.querySelector("#done-section .button-bottom").textContent = ciMsg.done;
}

function startup() {
    populateStrings();

    actionLocation = getJunctionName() + action;
    actionLocation = actionLocation.replace("authsvc", "apiauthsvc");
    setTimeout(poll, 2000);
}
