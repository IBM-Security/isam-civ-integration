// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("dialog-back-button").addEventListener("click", cancel);
    document.getElementById("verify_button").addEventListener("click", submit);
    document.getElementById("resendCodeLink").addEventListener("click", resendCode);
    document.getElementById("otp").addEventListener("input", function() {
        checkValid(this)
    });

    var jsLinks = document.querySelectorAll('[href="#"]');

    for (let i = 0; i < jsLinks.length; i++) {
        jsLinks[i].addEventListener("click", function(event) {
            event.preventDefault(); // Prevent default action (a following a link)
        }, false);
    }
});

var verify_errorMsg = document.currentScript.dataset.errorMessage;
var verify_correlation = document.currentScript.dataset.correlation;
var verify_type = document.currentScript.dataset.type;

function populateStrings() {
    document.title = ciMsg.authMethodVerification;
    document.querySelector('h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('h1').textContent = ciMsg.letsMakeSure;
    document.getElementById("otp").placeholder = ciMsg.accessTokenPlaceholder;
    document.getElementById("verify_button").value = ciMsg.verify;
    document.querySelectorAll("p")[2].textContent = ciMsg.accessCode;
    document.querySelector("a").textContent = ciMsg.resendCode;

    if (verify_correlation != "") {
        verify_correlation += " -";
    }

    if (verify_type == "smsotp" || verify_type == "transientsms") {
        document.getElementById("instructions").textContent = ciMsg.smsVerificationInstructions;
        document.getElementById("correlation").textContent = verify_correlation;

        document.getElementById("correlation").className = "textbox-left";
        document.getElementById("otp").className = "textbox-right";

        document.getElementById("verification_img").src = getJunctionName() + "/sps/static/design_images/credentials_bubble.svg";

        document.querySelector("a").classList.remove("hidden");
    } else if (verify_type == "emailotp" || verify_type == "transientemail") {
        document.getElementById("instructions").textContent = ciMsg.emailVerificationInstructions;
        document.getElementById("correlation").textContent = verify_correlation;

        document.getElementById("correlation").className = "textbox-left";
        document.getElementById("otp").className = "textbox-right";

        document.getElementById("verification_img").src = getJunctionName() + "/sps/static/design_images/envelope-open.svg";

        document.querySelector("a").classList.remove("hidden");
    } else if (verify_type == "totp") {
        document.getElementById("instructions").textContent = ciMsg.verifyVerificationInstructions;
        document.getElementById("otp").style["display"] = "block";
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
    document.getElementById("verify_button").disabled = !valid;

    return valid;
}

function submit() {
    var otpInput = document.getElementById("otp");
    var otp = otpInput.value;

    if (checkValid(otpInput, "otp")) {
        document.querySelector(".loader").classList.remove('hidden');
        document.getElementById("verification_img").classList.add('hidden');
        document.getElementById("verifyForm").otp.value = otp;
        document.getElementById("verifyForm").submit();
    }
}

function resendCode() {
    document.querySelector(".loader").classList.remove('hidden');
    document.getElementById("verification_img").classList.add('hidden');
    document.getElementById("resendForm").submit();
}

function cancel() {
    document.querySelector(".loader").classList.remove('hidden');
    document.getElementById("verification_img").classList.add('hidden');
    document.getElementById("cancelForm").submit();
}

function startup() {
    populateStrings();
    if (verify_errorMsg != null && verify_errorMsg != "") {
        var errorDiv = document.getElementById("error-msg");
        errorDiv.textContent = verify_errorMsg;
        errorDiv.style = "color: #dc0000;";
        errorDiv.classList.remove("hidden");
        document.getElementById("instructions").classList.add("hidden");
    }
    var input = document.querySelector('#otp');
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13, space is 32
        if (event.keyCode === 13 || event.keyCode == 32) {
            document.querySelector('#verify_button').click();
        }
    });
}
