// Copyright contributors to the IBM Security Verify Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("verify-button").addEventListener("click", function() {
        enroll('verify')
    });
    document.getElementById("totp-button").addEventListener("click", function() {
        enroll('totp')
    });
    document.getElementById("sms-button").addEventListener("click", function() {
        enroll('smsotp')
    });
    document.getElementById("email-button").addEventListener("click", function() {
        enroll('emailotp')
    });
    document.getElementById("emailotp-input").addEventListener("input", function() {
        checkValid(this, 'email-code-button')
    });
    document.getElementById("email-code-button").addEventListener("click", function() {
        enroll('emailotp')
    });
    document.getElementById("sms-code-button").addEventListener("click", function() {
        enroll('smsotp')
    });
    document.getElementById("smsotp-input").addEventListener("input", function() {
        checkValid(this, 'sms-code-button')
    });
    document.getElementById("countryDropdown").addEventListener("click", function() {
        countryDropdown(this)
    });

    var jsLinks = document.querySelectorAll('[href="#"]');

    for (let i = 0; i < jsLinks.length; i++) {
        jsLinks[i].addEventListener("click", function(event) {
            event.preventDefault(); // Prevent default action (a following a link)
        }, false);
    }
});


var je_countries = [ciMsg.AD, ciMsg.AT, ciMsg.AU, ciMsg.BE, ciMsg.BM, ciMsg.CA, ciMsg.CY, ciMsg.CZ, ciMsg.DK, ciMsg.EE, ciMsg.FO, ciMsg.FI, ciMsg.FR, ciMsg.DE, ciMsg.GR, ciMsg.GL, ciMsg.HK, ciMsg.IS, ciMsg.IN, ciMsg.IE, ciMsg.IL, ciMsg.IT, ciMsg.JP, ciMsg.LI, ciMsg.LU, ciMsg.MT, ciMsg.MC, ciMsg.NL, ciMsg.NZ, ciMsg.NO, ciMsg.PH, ciMsg.PL, ciMsg.PT, ciMsg.SM, ciMsg.SA, ciMsg.SG, ciMsg.SK, ciMsg.SI, ciMsg.ES, ciMsg.SE, ciMsg.CH, ciMsg.TH, ciMsg.AE, ciMsg.GB, ciMsg.US];
//["Andorra","Austria","Australia","Belgium","Bermuda","Canada","Cyprus","Czech Republic","Denmark","Estonia","Faroe Islands","Finland","France","Germany","Greece","Greenland","Hong Kong","Iceland","India","Ireland","Israel","Italy","Japan","Liechtenstein","Luxembourg","Malta","Monaco","Netherlands","New Zealand","Norway","Philippines","Poland","Portugal","San Marino","Saudi Arabia","Singapore","Slovakia","Slovenia","Spain","Sweden","Switzerland","Thailand","United Arab Emirates","United Kingdom","United States"];
var je_phoneCodes = {}; je_phoneCodes[ciMsg.AD] = "+376"; je_phoneCodes[ciMsg.AT] = "+43"; je_phoneCodes[ciMsg.AU] = "+61"; je_phoneCodes[ciMsg.BE] = "+32"; je_phoneCodes[ciMsg.BM] = "+809"; je_phoneCodes[ciMsg.CA] = "+1"; je_phoneCodes[ciMsg.CY] = "+357"; je_phoneCodes[ciMsg.CZ] = "+420"; je_phoneCodes[ciMsg.DK] = "+45"; je_phoneCodes[ciMsg.EE] = "+372"; je_phoneCodes[ciMsg.FO] = "+298"; je_phoneCodes[ciMsg.FI] = "+358"; je_phoneCodes[ciMsg.FR] = "+33"; je_phoneCodes[ciMsg.DE] = "+49"; je_phoneCodes[ciMsg.GR] = "+30"; je_phoneCodes[ciMsg.GL] = "+299"; je_phoneCodes[ciMsg.HK] = "+852"; je_phoneCodes[ciMsg.IS] = "+354"; je_phoneCodes[ciMsg.IN] = "+91"; je_phoneCodes[ciMsg.IE] = "+353"; je_phoneCodes[ciMsg.IL] = "+972"; je_phoneCodes[ciMsg.IT] = "+39"; je_phoneCodes[ciMsg.JP] = "+81"; je_phoneCodes[ciMsg.LI] = "+423"; je_phoneCodes[ciMsg.LU] = "+352"; je_phoneCodes[ciMsg.MT] = "+356"; je_phoneCodes[ciMsg.MC] = "+33"; je_phoneCodes[ciMsg.NL] = "+31"; je_phoneCodes[ciMsg.NZ] = "+64"; je_phoneCodes[ciMsg.NO] = "+47"; je_phoneCodes[ciMsg.PH] = "+63"; je_phoneCodes[ciMsg.PL] = "+48"; je_phoneCodes[ciMsg.PT] = "+351"; je_phoneCodes[ciMsg.SM] = "+378"; je_phoneCodes[ciMsg.SA] = "+966"; je_phoneCodes[ciMsg.SG] = "+65"; je_phoneCodes[ciMsg.SK] = "+421"; je_phoneCodes[ciMsg.SI] = "+386"; je_phoneCodes[ciMsg.ES] = "+34"; je_phoneCodes[ciMsg.SE] = "+46"; je_phoneCodes[ciMsg.CH] = "+41"; je_phoneCodes[ciMsg.TH] = "+66"; je_phoneCodes[ciMsg.AE] = "+971"; je_phoneCodes[ciMsg.GB] = "+44"; je_phoneCodes[ciMsg.US] = "+1";

var je_jitType = document.currentScript.dataset.jitTypeTag;
var je_enabledMethods = document.currentScript.dataset.enabledMethodsTag;

function unhideMethods() {

    if (je_enabledMethods && je_enabledMethods.length > 0) {
        je_enabledMethods = JSON.parse(je_enabledMethods.replace(/&quot;/g, '"'));

        var includeTOTP = je_enabledMethods.indexOf("TOTP") != -1;
        var includeSMS = je_enabledMethods.indexOf("SMSOTP") != -1;
        var includeEmail = je_enabledMethods.indexOf("EmailOTP") != -1;
        var includeVerify = je_enabledMethods.indexOf("Verify") != -1;

        if (includeTOTP) {
            document.getElementById("totp-method-container").classList.remove("hidden");
        }
        if (includeSMS) {
            document.getElementById("sms-method-container").classList.remove("hidden");
        }
        if (includeEmail) {
            document.getElementById("email-method-container").classList.remove("hidden");
        }
        if (includeVerify) {
            document.getElementById("verify-button").disabled = false;
        }
    }
}

function enroll(type) {
    if (je_jitType != null && je_jitType != "") {
        if (type == "emailotp" || type == "smsotp") {
            var otpDeliveryInput = document.getElementById(type + "-input");
            var otpDelivery = otpDeliveryInput.value;

            if (type == "smsotp") {
                document.querySelectorAll(".loader")[2].classList.remove('hidden');
                document.querySelectorAll(".welcome-illustrations .launch-animation")[2].classList.add('hidden');
                var countryArray = document.getElementById("countryDropdown").textContent.split(" ");
                var code = countryArray[countryArray.length - 1];
                otpDelivery = code + otpDelivery;
            } else {
                document.querySelectorAll(".loader")[1].classList.remove('hidden');
                document.querySelectorAll(".welcome-illustrations .launch-animation")[1].classList.add('hidden');
            }
            var input = document.createElement("input");
            input.type = "hidden";
            input.name = "otpDelivery";
            input.value = otpDelivery;
            document.getElementById("enrollForm").appendChild(input);
            document.getElementById("enrollForm").otpDelivery.value = otpDelivery;
        } else {
            if (type == "verify") {
                document.getElementById("verify-button").disabled = true;
            }
            document.querySelectorAll(".loader")[0].classList.remove('hidden');
        }
        document.getElementById("enrollForm").type.value = type;
        document.getElementById("enrollForm").submit();
    } else {
        document.getElementById("secondFactorForm").jitType.value = type;
        document.getElementById("secondFactorForm").submit();
        if (type == "verify") {
            document.getElementById("verify-button").disabled = true;
        }
        document.querySelectorAll(".loader")[0].classList.remove('hidden');
    }
}

function showEmailPrompt() {
    document.getElementById("enroll-section").classList.remove('notransition');
    document.getElementById("enroll-section").classList.remove('dialog-content--visible');
    document.getElementById("enroll-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("enroll-section").style.left = '-100%';
        document.querySelectorAll(".loader")[0].classList.add('hidden');
    }, 300);
    document.getElementById("email-section").style.left = '';
    document.getElementById("email-section").classList.add('dialog-content--visible');
}

function showSMSPrompt() {
    var dropdownList = document.querySelector('.dropdown-list');
    for (var i = 0; i < je_countries.length; i++) {
        var entry = document.createElement('li');
        entry.textContent = je_countries[i] + " " + je_phoneCodes[je_countries[i]];
        entry.onclick = function() {
            document.getElementById("countryDropdown").textContent = this.textContent;
        };
        dropdownList.appendChild(entry);
    }
    document.getElementById("enroll-section").classList.remove('notransition');
    document.getElementById("enroll-section").classList.remove('dialog-content--visible');
    document.getElementById("enroll-section").classList.add('dialog-content--hidden');
    setTimeout(function() {
        document.getElementById("enroll-section").style.left = '-100%';
        document.querySelectorAll(".loader")[0].classList.add('hidden');
    }, 300);
    document.getElementById("sms-section").style.left = '';
    document.getElementById("sms-section").classList.add('dialog-content--visible');
}

function back() {
    document.getElementById("sms-section").classList.remove('dialog-content--visible');
    setTimeout(function() {
        document.getElementById("sms-section").style.left = '100%';
    }, 300);
    document.getElementById("email-section").classList.remove('dialog-content--visible');
    setTimeout(function() {
        document.getElementById("email-section").style.left = '100%';
    }, 300);
    document.getElementById("enroll-section").style.left = '';
    document.getElementById("enroll-section").classList.remove('dialog-content--hidden');
    document.getElementById("enroll-section").classList.add('dialog-content--visible');
}

function checkValid(input, buttonId) {
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
    document.getElementById(buttonId).disabled = !valid;

    return valid;
}

function countryDropdown(button) {
    if (button.parentNode.children[1].style.display == "block") {
        button.parentNode.children[1].style.display = "none";
    } else {
        button.parentNode.children[1].style.display = "block";
    }
};

function populateStrings() {
    document.title = ciMsg.chooseMethod;
    document.getElementById("countryDropdown").textContent = ciMsg.US + " " + je_phoneCodes[ciMsg.US];
    document.querySelector("#enroll-section h3").textContent = ciMsg.recommended;
    document.querySelector("#enroll-section h1").textContent = ciMsg.setupIBMVerify;
    document.querySelector("p").innerHTML = ciMsg.verifyEnrollDesc;
    document.querySelector("#enroll-section #verify-button").textContent = ciMsg.setUp;
    document.querySelector("#enroll-section #totp-method-container b").textContent = ciMsg.mobileApp;
    document.querySelector("#enroll-section #totp-method-container p").textContent = ciMsg.totpEnrollDesc;
    document.querySelector("#enroll-section #totp-button").textContent = ciMsg.setUp;
    document.querySelector("#enroll-section #sms-method-container b").textContent = ciMsg.textMessage;
    document.querySelector("#enroll-section #sms-method-container p").textContent = ciMsg.smsEnrollDesc;
    document.querySelector("#enroll-section #sms-button").textContent = ciMsg.setUp;
    document.querySelector("#enroll-section #email-method-container b").textContent = ciMsg.email;
    document.querySelector("#enroll-section #email-method-container p").textContent = ciMsg.emailEnrollDesc;
    document.querySelector("#enroll-section #email-button").textContent = ciMsg.setUp;
    document.querySelector("#email-section h1").textContent = ciMsg.enterEmail;
    document.querySelectorAll("#email-section p")[0].textContent = ciMsg.emailPromptDesc;
    document.querySelectorAll("#email-section p")[1].textContent = ciMsg.emailAddress;
    document.getElementById("emailotp-input").placeholder = ciMsg.enterEmailAddress;
    document.getElementById("emailotp-input").style.width = document.getElementById("emailotp-input").getAttribute('placeholder').length * 8 + 12 + "px";
    document.getElementById("email-code-button").textContent = ciMsg.sendAccessCode;
    document.querySelector("#sms-section h1").textContent = ciMsg.enterMobile;
    document.querySelectorAll("#sms-section p")[0].textContent = ciMsg.smsPromptDesc;
    document.querySelectorAll("#sms-section p")[1].textContent = ciMsg.country;
    document.querySelectorAll("#sms-section p")[2].textContent = ciMsg.mobileNumber;
    document.getElementById("smsotp-input").placeholder = ciMsg.enterMobileAreaCode;
    document.getElementById("smsotp-input").style.width = document.getElementById("smsotp-input").getAttribute('placeholder').length * 8 + 12 + "px";
    document.getElementById("sms-code-button").textContent = ciMsg.sendAccessCode;
}

function configureEvent(inputSelector, buttonSelector) {
    var input = document.querySelector(inputSelector);
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13, space is 32
        if (event.keyCode === 13 || event.keyCode == 32) {
            document.querySelector(buttonSelector).click();
        }
    });
}

function startup() {
    populateStrings();
    unhideMethods();

    document.addEventListener('click', function(event) {
        if (!event.target.classList.contains('more-menu')) {
            var cardMenus = document.querySelectorAll('.dropdown-list');
            for (var i = 0; i < cardMenus.length; i++) {
                cardMenus[i].style.display = '';
            }
        }
    });
    configureEvent('#email-section input', '#email-section #email-code-button');
    configureEvent('#sms-section input', '#sms-section #sms-code-button');

    if (je_jitType != null && je_jitType != "") {
        if (je_jitType == "smsotp") {
            showSMSPrompt();
        } else if (je_jitType == "emailotp") {
            showEmailPrompt();
        }
    }
}
