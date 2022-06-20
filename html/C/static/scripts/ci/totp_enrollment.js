window.addEventListener('load', (event) => {
    startup();
    document.getElementById("button-1").addEventListener("click", showConnect);
    document.getElementById("button-2").addEventListener("click", showValidation);
    document.getElementById("otp").addEventListener("input", function() {
        checkValid(this)
    });
    document.getElementById("validate-button").addEventListener("click", function() {
        validateOtp(this)
    });
});

var totpe_errorMsg = document.currentScript.dataset.errorTag;

function showConnect() {
    document.getElementById("download-section").classList.remove('dialog-content--visible');
    document.getElementById("download-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("download-section").style.left = '-100%';
    }, 300);
    document.getElementById("connect-section").style.left = '';
    document.getElementById("connect-section").classList.add('dialog-content--visible');
}

function validateOtp(button) {
    var container = button.parentNode.parentNode;
    var otpInput = container.querySelector('#otp');
    var otp = otpInput.value;

    if (checkValid(otpInput, "otp")) {
        document.querySelector(".loader").classList.remove('hidden');
        document.querySelector(".welcome-illustrations .launch-animation").classList.add('hidden');
        document.getElementById("validateForm").otp.value = otp;
        document.getElementById("validateForm").submit();
    }
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
    document.getElementById("validate-button").disabled = !valid;

    return valid;
}

function populateStrings() {
    document.title = ciMsg.totpApp;
    document.querySelector('#download-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#download-section h1').textContent = ciMsg.downloadApp;
    document.querySelector('#download-section p').textContent = ciMsg.downloadOrNextGeneric;
    document.querySelectorAll('#download-section .ordered-list li')[0].innerHTML = ciMsg.launchAppStore;
    document.querySelectorAll('#download-section .ordered-list li')[1].textContent = ciMsg.searchForApp;
    document.querySelectorAll('#download-section .ordered-list li')[2].textContent = ciMsg.install;
    document.querySelector("#download-section .button-bottom").textContent = ciMsg.nextConnectAccount;

    document.querySelector('#connect-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#connect-section h1').textContent = ciMsg.connectYourAccount;
    document.querySelector('#connect-section p').textContent = ciMsg.connectYourAccountDesc;
    document.querySelector('#connect-section .ordered-list').children[0].textContent = ciMsg.launchApp;
    document.querySelector('#connect-section .ordered-list').children[1].textContent = ciMsg.tapToConnect;
    document.querySelector('#connect-section .ordered-list').children[2].textContent = ciMsg.scanQRCode;
    document.querySelector('#connect-section .qr-code#qrCode .scan b').textContent = ciMsg.scanMe;
    document.querySelectorAll('#connect-section .qr-code-error .scan b')[0].textContent = ciMsg.qrCodeError;
    document.querySelector("#connect-section .button-bottom").textContent = ciMsg.letsTry;

    document.querySelector('#validation-section h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('#validation-section h1').textContent = ciMsg.letsTry;
    document.getElementById("instructions").textContent = ciMsg.totpVerificationInstructions;
    document.querySelectorAll("#validation-section p")[2].textContent = ciMsg.accessCode;
    document.getElementById("otp").placeholder = ciMsg.enterCode;
    document.querySelector("#validation-section .button-bottom").textContent = ciMsg.validate;
}

function startup() {
    populateStrings();

    if (totpe_errorMsg != null && totpe_errorMsg != "") {
        showValidation()
        var errorDiv = document.getElementById("error-msg");
        errorDiv.textContent = totpe_errorMsg.includes("CSIAH0619E") ? ciMsg.validationFailed : totpe_errorMsg;
        errorDiv.style = "color: #dc0000;";
        errorDiv.classList.remove("hidden");
        document.getElementById("instructions").classList.add("hidden");
    }

    var input = document.querySelector('#otp');
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13, space is 32
        if (event.keyCode === 13 || event.keyCode == 32) {
            document.querySelector('#validate-button').click();
        }
    });
}
