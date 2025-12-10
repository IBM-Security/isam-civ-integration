// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("otp").addEventListener("input", function() {
        checkValid(this)
    });
    document.getElementById("validateButton").addEventListener("click", function() {
        validateOtp(this)
    });
    document.getElementById("button-connect").addEventListener("click", showConnect);
});

var vr_errorMsg = document.currentScript.dataset.errorTag;

function showConnect() {
    document.getElementById("download-section").classList.remove('dialog-content--visible');
    document.getElementById("download-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("download-section").style.left = '-100%';
    }, 300);
    document.getElementById("connect-section").style.left = '';
    document.getElementById("connect-section").classList.add('dialog-content--visible');
    setTimeout(pollEnrollment, 2000);
}

function showValidation() {
    document.getElementById("connect-section").classList.remove('dialog-content--visible');
    document.getElementById("connect-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("connect-section").style.left = '-100%';
    }, 300);
    document.getElementById("validation-section").style.left = '';
    document.getElementById("validation-section").classList.add('dialog-content--visible');

    setTimeout(function() {
        document.getElementById("otp").focus();
    }, 300);
}

function validateOtp(button) {
    var container = button.parentNode.parentNode;
    var otpInput = container.querySelector('#otp');
    var otp = otpInput.value;

    if (checkValid(otpInput, "otp")) {
        document.querySelectorAll(".loader")[1].classList.remove('hidden');
        document.querySelector(".welcome-illustrations .launch-animation").classList.add('hidden');
        document.getElementById("validateForm").otp.value = otp;
        document.getElementById("validateForm").action = vr_actionLocation.replace("apiauthsvc", "authsvc");
        document.getElementById("validateForm").submit();
    }
}

function checkValid(input) {
    var valid = false;
    var value = input.value;
    if (value != null && value != "" && input.validity.valid) {
        valid = true;
    }
    if (valid) {
        if (input.classList.contains('input-invalid')) {
            input.classList.remove('input-invalid');
        }
    } else {
        input.classList.add('input-invalid');
    }
    input.parentNode.parentNode.querySelector('.button-1.button-bottom').disabled = !valid;

    return valid;
}

var vr_pollCount = 30;
var vr_action = document.currentScript.dataset.action;
var vr_actionLocation = "";

function pollEnrollment() {
    if (vr_pollCount > 0) {
        var data = {
            "action": "pollEnrollment"
        };
        var pollRequest = new XMLHttpRequest();
        pollRequest.onreadystatechange = function() {
            processPollRequest(pollRequest);
        };
        pollRequest.open("PUT", vr_actionLocation, true);
        pollRequest.setRequestHeader("Accept", "application/json");
        pollRequest.setRequestHeader("Content-Type", "application/json");
        pollRequest.send(JSON.stringify(data));
        vr_pollCount--;
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
                vr_actionLocation = json.location;
            }
            if (json.status == "success") {
                document.querySelectorAll('.success-check')[0].style.display = 'block';
                setTimeout(function() {
                    document.getElementById("chooseMethodForm").type.value = "signature";
                    document.getElementById("chooseMethodForm").action = vr_actionLocation.replace("apiauthsvc", "authsvc");
                    document.getElementById("chooseMethodForm").submit();
                }, 500)
            } else if (json.status == "successWithTOTP") {
                document.querySelectorAll('.success-check')[0].style.display = 'block';
                setTimeout(showValidation, 500);
            } else if (json.status == "pending") {
                setTimeout(pollEnrollment, 2000);
            } else {
                // We most likely got an error when trying to poll.
                // Stop polling by setting pollCount to 0.
                vr_pollCount = 0;
            }
        } else {
            // We most likely got an error when trying to poll.
            // Stop polling by setting pollCount to 0.
            vr_pollCount = 0;
            if (json != null && json.location != null && json.location != "") {
                vr_actionLocation = json.location;
            }
        }
    }
}

function populateStrings() {
    document.title = ciMsg.ibmVerify;
    document.querySelector('#download-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#download-section h1').textContent = ciMsg.downloadApp;
    document.querySelector('#download-section p').textContent = ciMsg.downloadOrNext;
    PARSE_AND_ADD_MSG(ciMsg.launchAppStore, document.querySelectorAll('#download-section .ordered-list li')[0]);
    document.querySelectorAll('#download-section .ordered-list li')[1].textContent = ciMsg.searchForVerify;
    document.querySelectorAll('#download-section .ordered-list li')[2].textContent = ciMsg.install;
    document.querySelector("#download-section .button-bottom").textContent = ciMsg.nextConnectAccount;

    document.querySelector('#connect-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#connect-section h1').textContent = ciMsg.connectYourAccount;
    document.querySelector('#connect-section p').textContent = ciMsg.connectYourAccountDesc;
    document.querySelectorAll("#connect-section .ordered-list li")[0].textContent = ciMsg.launchIBMVerify;
    document.querySelectorAll("#connect-section .ordered-list li")[1].textContent = ciMsg.tapConnectAccount;
    document.querySelectorAll("#connect-section .ordered-list li")[2].textContent = ciMsg.scanQRCode;
    document.querySelector('.qr-code#qrCode .scan b').textContent = ciMsg.scanMe;
    document.querySelector('.qr-code-error .scan b').textContent = ciMsg.qrCodeError;

    document.querySelector('#validation-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#validation-section h1').textContent = ciMsg.letsTry;
    document.getElementById("instructions").textContent = ciMsg.verifyAppVerificationInstructions;
    document.querySelectorAll("#validation-section p")[2].textContent = ciMsg.accessCode;
    document.getElementById("otp").placeholder = ciMsg.enterCode;
    document.querySelector("#validation-section .button-bottom").textContent = ciMsg.validate;
}

function PARSE_AND_ADD_MSG(msg, elem) {
	const parser = new DOMParser();
	const doc = parser.parseFromString(msg, "text/html");
	const hasElements = doc.body.children.length > 0;
    if (hasElements) {
      // Treat as HTML
      doc.body.childNodes.forEach(node => {
        elem.appendChild(node.cloneNode(true));
      });
    } else {
      // Treat as plain text
      const textNode = document.createTextNode(doc.body.textContent);
      elem.appendChild(textNode);
    }
}

function startup() {
    populateStrings();

    vr_actionLocation = getJunctionName() + vr_action;
    vr_actionLocation = vr_actionLocation.replace("authsvc", "apiauthsvc");

    if (vr_errorMsg != null && vr_errorMsg != "") {
        showValidation()
        var errorDiv = document.getElementById("error-msg");
        errorDiv.textContent = vr_errorMsg;
        errorDiv.style = "color: #dc0000;";
        errorDiv.classList.remove("hidden");
        document.getElementById("instructions").classList.add("hidden");
    }

    var input = document.querySelector('#validation-section #otp');
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13, space is 32
        if (event.keyCode === 13 || event.keyCode == 32) {
            document.querySelector('#validation-section .button-bottom').click();
        }
    });
}
