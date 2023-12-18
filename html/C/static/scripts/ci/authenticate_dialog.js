// Copyright contributors to the IBM Security Verify Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
});

var ad_data_tags = document.getElementById('authenticate-methods-tag');

var methodsJSON = JSON.parse(ad_data_tags.textContent);
var ad_auth_methods = methodsJSON["authMethods"];
var ad_signature_methods = methodsJSON["signatureMethods"]
var ad_transient_methods = methodsJSON["transMethods"];

var ad_expand_verify_methods = ad_data_tags.dataset.expandVerifyMethods;
var ad_jit_enrollment = ad_data_tags.dataset.jitEnrollment;
var ad_hide_transient = ad_data_tags.dataset.hideTransientIfEnroll;
var ad_enabled_methods = ad_data_tags.dataset.enabledMethods;

var include_totp = false;
var include_sms = false;
var include_email = false;
var include_verify = false;

if (ad_enabled_methods && ad_enabled_methods.length > 0) {
    ad_enabled_methods = JSON.parse(ad_enabled_methods.replace(/&quot;/g, '"'));

    include_totp = ad_enabled_methods.indexOf("TOTP") != -1;
    include_sms = ad_enabled_methods.indexOf("SMSOTP") != -1;
    include_email = ad_enabled_methods.indexOf("EmailOTP") != -1;
    include_verify = ad_enabled_methods.indexOf("Verify") != -1;
}

function createGrid() {

    var verify_method_div = document.getElementById("verify-method-container");
    var totp_method_div = document.getElementById("totp-method-container");
    var sms_method_div = document.getElementById("sms-method-container");
    var email_method_div = document.getElementById("email-method-container");

    var verify_method_title = document.createElement('div');
    var verify_title_bold = document.createElement('b');
    verify_title_bold.textContent = ciMsg["ibmVerifyApp"];
    verify_method_title.appendChild(verify_title_bold);
    verify_method_div.appendChild(verify_method_title);

    var totp_method_title = document.createElement('div');
    var totp_title_bold = document.createElement('b');
    totp_title_bold.textContent = ciMsg["totpApp"];
    totp_method_title.appendChild(totp_title_bold);
    totp_method_div.appendChild(totp_method_title);

    var email_method_title = document.createElement('div');
    var email_title_bold = document.createElement('b');
    email_title_bold.textContent = ciMsg["email"];
    email_method_title.appendChild(email_title_bold);
    email_method_div.appendChild(email_method_title);

    var sms_method_title = document.createElement('div');
    var sms_title_bold = document.createElement('b');
    sms_title_bold.textContent = ciMsg["textMessage"];
    sms_method_title.appendChild(sms_title_bold);
    sms_method_div.appendChild(sms_method_title);

    for (var i = 0; i < ad_auth_methods.length; i++) {
        var method = ad_auth_methods[i];

        var id = method['id'];
        var creationDate = new Date(method['creationTime']);

        var type = method['type'];
        var enabled = method['enabled'];
        if((type == "emailotp" && !include_email) ||
                (type == "smsotp" && !include_sms) ||
                (type == "totp" && !include_totp)) {
            continue;
        }

        if (type != "signature" && enabled) {
            var method_div = document.createElement('div');
            method_div.className = "line-method";
            method_div.id = id;
            method_div.type = type;

            method_div.onclick = function() {
                document.querySelector(".layout-left .loader").classList.remove('hidden');
                document.querySelector(".layout-left .welcome-illustrations .launch-animation").classList.add('hidden');
                document.getElementById("chooseMethodForm").type.value = this.type;
                document.getElementById("chooseMethodForm").id.value = this.id;
                document.getElementById("chooseMethodForm").submit();
            };

            method_div.addEventListener("keyup", function(event) {
                event.preventDefault();
                // Enter key is 13, space is 32
                if (event.keyCode === 13 || event.keyCode == 32) {
                    this.click();
                }
            });

            var prettyType = ciMsg["totpApp"];
            var sendText = ciMsg["totpApp"];
            var extraInfo = "";
            if (type == "emailotp") {
                prettyType = ciMsg["email"];
                extraInfo = method['attributes'].emailAddress;
            } else if (type == "smsotp") {
                prettyType = ciMsg["textMessage"];
                extraInfo = method['attributes'].phoneNumber;
            }
            extraInfo = extraInfo.replace(/\*/g, "•");

            var type_div = document.createElement('div');
            type_div.className = "method-type";
            type_div.textContent = extraInfo;
            method_div.appendChild(type_div);

            var link_div = document.createElement('a');
            link_div.className = "method-link";
            link_div.href = "#";
            link_div.textContent = type == "totp" ? ciMsg.enterCode : ciMsg.sendCode;
            link_div.id = id;
            link_div.type = type;

            link_div.addEventListener("click", function(event) {
                event.preventDefault(); // Prevent default action (a following a link)
            }, false);

            method_div.appendChild(link_div);

            if (type == "smsotp") {
                sms_method_div.appendChild(method_div);
            } else if (type == "emailotp") {
                email_method_div.appendChild(method_div);
            } else if (type == "totp") {
                totp_method_div.appendChild(method_div);
            }
        }
    }

    if(include_verify) {
        for (var i = 0; i < ad_signature_methods.length; i++) {

            var signature_method = ad_signature_methods[i];
            var id = signature_method['id'];
            var authenticator = signature_method["_embedded"];
            var authenticatorId = authenticator['id'];

            var enabled = authenticator['enabled'];
            if (enabled) {
                var type = signature_method["type"];
                var subType = signature_method["subType"];

                var method_div = document.createElement('div');
                method_div.className = "line-method";
                method_div.id = id;
                method_div.type = type;

                method_div.onclick = function() {
                    document.querySelector(".layout-left .loader").classList.remove('hidden');
                    document.querySelector(".layout-left .welcome-illustrations .launch-animation").classList.add('hidden');
                    document.getElementById("chooseMethodForm").type.value = this.type;
                    document.getElementById("chooseMethodForm").id.value = this.id;
                    document.getElementById("chooseMethodForm").submit();
                };

                method_div.addEventListener("keyup", function(event) {
                    event.preventDefault();
                    // Enter key is 13, space is 32
                    if (event.keyCode === 13 || event.keyCode == 32) {
                        this.click();
                    }
                });

                var type_div = document.createElement('div');
                type_div.className = "method-type";
                var description = authenticator.attributes.deviceName + ' (' + authenticator.attributes.deviceType + " " + (authenticator.attributes.deviceType.startsWith("i") ? ciMsg.ios + " " : ciMsg.android + " ") + authenticator.attributes.osVersion + ')';
                if (ad_expand_verify_methods === "true" || ad_expand_verify_methods === true) {
                    description = authenticator.attributes.deviceName + " - " + ciMsg[subType];
                }
                type_div.textContent = description
                method_div.appendChild(type_div);

                var link_div = document.createElement('a');
                link_div.className = "method-link";
                link_div.href = "#";
                link_div.textContent = ciMsg.sendPush;
                link_div.id = id;
                link_div.type = type;

                link_div.addEventListener("click", function(event) {
                    event.preventDefault(); // Prevent default action (a following a link)
                }, false);

                method_div.appendChild(link_div);

                verify_method_div.appendChild(method_div);
            }
        }
    }

    for (var i = 0; i < ad_transient_methods.length; i++) {

        var transient_method = null;
        var transient_value = null;
        var keys = Object.keys(ad_transient_methods[i]);

        if (keys.length > 0) {
            transient_method = keys[0];
            transient_value = ad_transient_methods[i][transient_method];
        }

        if ((ad_hide_transient == "true" || ad_hide_transient == true) && (
                (transient_method == "transientsms" && sms_method_div.children.length > 1) ||
                (transient_method == "transientemail" && email_method_div.children.length > 1))) {
            continue;
        }

        var method_div = document.createElement('div');
        method_div.className = "line-method";
        method_div.type = transient_method;

        method_div.onclick = function() {
            document.querySelector(".layout-left .loader").classList.remove('hidden');
            document.querySelector(".layout-left .welcome-illustrations .launch-animation").classList.add('hidden');
            document.getElementById("chooseMethodForm").type.value = this.type;
            document.getElementById("chooseMethodForm").submit();
        };

        method_div.addEventListener("keyup", function(event) {
            event.preventDefault();
            // Enter key is 13, space is 32
            if (event.keyCode === 13 || event.keyCode == 32) {
                this.click();
            }
        });

        var prettyType = ciMsg["textMessage"];
        var extraInfo = transient_value.replace(/\*/g, "•");
        if (transient_method == "transientemail") {
            prettyType = ciMsg["email"];
        }

        var type_div = document.createElement('div');
        type_div.className = "method-type";
        type_div.textContent = extraInfo;
        method_div.appendChild(type_div);

        var link_div = document.createElement('a');
        link_div.className = "method-link";
        link_div.href = "#";
        link_div.textContent = ciMsg.sendCode;
        link_div.id = transient_method;
        link_div.type = transient_method;

        link_div.addEventListener("click", function(event) {
            event.preventDefault(); // Prevent default action (a following a link)
        }, false);

        method_div.appendChild(link_div);
        if (transient_method == "transientsms") {
            sms_method_div.appendChild(method_div);
        } else if (transient_method == "transientemail") {
            email_method_div.appendChild(method_div);
        }
    }

    if (ad_auth_methods.length == 0 && ad_signature_methods.length == 0 && ad_transient_methods.length == 0) {
        document.getElementById("empty-method-container").classList.remove("hidden");
    } else if (ad_auth_methods.length == 0 && ad_signature_methods.length == 0 && (ad_jit_enrollment === "true" || ad_jit_enrollment === true)) {
        document.getElementById("jit-enrollment-container").classList.remove("hidden");
    }

    if (verify_method_div.children.length > 1) {
        verify_method_div.appendChild(document.createElement('hr'));
        verify_method_div.classList.remove("hidden");
    }
    if (totp_method_div.children.length > 1) {
        totp_method_div.appendChild(document.createElement('hr'));
        totp_method_div.classList.remove("hidden");
    }
    if (sms_method_div.children.length > 1) {
        sms_method_div.appendChild(document.createElement('hr'));
        sms_method_div.classList.remove("hidden");
    }
    if (email_method_div.children.length > 1) {
        email_method_div.appendChild(document.createElement('hr'));
        email_method_div.classList.remove("hidden");
    }
}

function enrollPrompt() {
    document.querySelector(".layout-left .loader").classList.remove('hidden');
    document.querySelector(".layout-left .welcome-illustrations .launch-animation").classList.add('hidden');
    document.getElementById("enrollPromptForm").submit();
}

function populateStrings() {
    document.title = ciMsg.authMethodSelection;
    document.querySelector('h3').textContent = ciMsg.twoStepVeri;
    document.querySelector('h1').textContent = ciMsg.chooseAMethod;
    document.getElementById('verify-question').textContent = ciMsg.howToVerify;
    document.querySelectorAll('p')[1].textContent = ciMsg.whoopsNoMethods;
    if (ciMsg.useADifferentMethod) {
        document.querySelectorAll('p')[2].innerHTML = ciMsg.useADifferentMethod + ' <a href="#" id="enrollPromptOnClick">' + ciMsg.enrollNow + '</a>';
        document.getElementById("enrollPromptOnClick").addEventListener("click", function(event) {
            enrollPrompt();
            event.preventDefault(); // Prevent default action (a following a link)
        }, false);
    }
}

function startup() {
    populateStrings();
    createGrid();
}
