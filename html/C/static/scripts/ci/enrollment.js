// Copyright contributors to the IBM Security Verify Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("otp").addEventListener('input', function() {
        checkValid(this);
    });
    document.getElementById("verify-button").addEventListener('click', function() {
        validateOtp(this);
    });
});

var cienr_type = document.currentScript.dataset.type;
var cienr_correlation = document.currentScript.dataset.correlation;

function validateOtp(button) {
    document.querySelector(".loader").classList.remove('hidden');
    document.querySelector(".welcome-illustrations .launch-animation").classList.add('hidden');
    var container = button.parentNode.parentNode;
    var otpInput = container.querySelector('#otp');
    var otp = otpInput.value;

    if (checkValid(otpInput, "otp")) {
        document.getElementById("validateForm").type.value = cienr_type;
        document.getElementById("validateForm").otp.value = otp;
        document.getElementById("validateForm").submit();
    }
}

function showValidation() {
    document.getElementById("qrcode-section").classList.remove('dialog-content--visible');
    document.getElementById("qrcode-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("qrcode-section").style.left = '-100%';
    }, 300);
    document.getElementById("validation-section").style.left = '';
    document.getElementById("validation-section").classList.add('dialog-content--visible');
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
    document.getElementById("verify-button").disabled = !valid;

    return valid;
}

function populateStrings() {
    document.title = ciMsg.letsTry;
    document.getElementById("correlation").textContent = cienr_correlation + " -";
    if (cienr_type == "smsotp") {
        document.querySelector('#validation-section h3').textContent = ciMsg.verifyMobile;
        document.querySelector('#validation-section p').textContent = ciMsg.smsCodeDesc;
        document.querySelector("img").src = getJunctionName() + "/sps/static/design_images/credentials_bubble.svg";
    } else {
        document.querySelector('#validation-section h3').textContent = ciMsg.verifyEmail;
        document.querySelector('#validation-section p').textContent = ciMsg.emailCodeDesc;
        document.querySelector("img").src = getJunctionName() + "/sps/static/design_images/envelope-open.svg";
    }
    document.querySelector('#validation-section h1').textContent = ciMsg.letsTry;
    document.querySelectorAll("#validation-section p")[1].textContent = ciMsg.accessCode;
    document.getElementById("otp").placeholder = ciMsg.enterCode;
    document.querySelector("#validation-section .button-bottom").textContent = ciMsg.verify;
}

function startup() {
    populateStrings();

    var input = document.querySelector('#validation-section #otp');
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13, space is 32
        if (event.keyCode === 13 || event.keyCode == 32) {
            document.querySelector('#validation-section #verify-button').click();
        }
    });
}
