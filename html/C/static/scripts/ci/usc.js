// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();

    document.getElementById("chooseMobileButton").addEventListener("click", function() {
        showContentSection(this)
    });
    document.getElementById("chooseEmailButton").addEventListener("click", function() {
        showContentSection(this)
    });
    document.getElementById("chooseVerifyButton").addEventListener("click", function() {
        showContentSection(this)
    });
    document.getElementById("chooseTotpButton").addEventListener("click", function() {
        showContentSection(this)
    });
    document.getElementById("chooseSmsButton").addEventListener("click", function() {
        showContentSection(this)
    });
    document.getElementById("closeOrTotpButton").addEventListener("click", function() {
        closeOrTotpValidation(this)
    });
    document.getElementById("register-authenticator-button").addEventListener("click", function() {
        registerAuthenticatorOrTOTP(this)
    });

    document.getElementById("countryDropdown").addEventListener("click", function() {
        countryDropDown(this)
    });
    document.getElementById("smsOtpDelivery").addEventListener("input", function() {
        checkValid(this, 'smsotp')
    });
    document.getElementById("enrolSmsButton").addEventListener("click", function() {
        enrollSMSorEmail('smsotp', '#smsOtpDelivery', this)
    });
    document.getElementById("emailOtpDelivery").addEventListener("input", function() {
        checkValid(this, 'emailotp')
    });
    document.getElementById("enrolEmailButton").addEventListener("click", function() {
        enrollSMSorEmail('emailotp', '#emailOtpDelivery', this)
    });
    document.getElementById("closeButton").addEventListener("click", closeDialog);
    document.getElementById("smsOtp").addEventListener("input", function() {
        checkValid(this, 'otp')
    });
    document.getElementById("emailOtp").addEventListener("input", function() {
        checkValid(this, 'otp')
    });
    document.getElementById("totpOtp").addEventListener("input", function() {
        checkValid(this, 'otp')
    });
    document.getElementById("validateSmsButton").addEventListener("click", function() {
        validateOtp('smsotp', '#smsOtp', this)
    });
    document.getElementById("validateEmailButton").addEventListener("click", function() {
        validateOtp('emailotp', '#emailOtp', this)
    });
    document.getElementById("validateTotpButton").addEventListener("click", function() {
        validateOtp('totp', '#totpOtp', this)
    });
    document.getElementById("registerButton").addEventListener("click", launchRegisterDialog);
    document.getElementById("backLink").addEventListener("click", dialogBack);
    document.getElementById("closeLink").addEventListener("click", closeDialog);
    document.getElementById("learnmore").addEventListener("click", learnMore);

    var jsLinks = document.querySelectorAll('[href="#"]');

    for (let i = 0; i < jsLinks.length; i++) {
        jsLinks[i].addEventListener("click", function(event) {
            event.preventDefault(); // Prevent default action (a following a link)
        }, false);
    }
});

var scriptElem = document.getElementById("usc-data-tag-holder");
var scriptJson = JSON.parse(scriptElem.textContent);

var usc_methods = scriptJson["authMethods"];
var usc_authenticators = scriptJson["authenticators"];
var usc_action = scriptElem.dataset.action;
var usc_enabledMethods = scriptElem.dataset.enabledMethods;
var usc_name = scriptElem.dataset.name
var usc_actionLocation = "";

var refreshRequired = false;

function startup() {
    populateDevices();
    populateStrings();

    usc_enabledMethods = JSON.parse(usc_enabledMethods.replace(/&quot;/g, '"'));
    var includeTOTP = usc_enabledMethods.indexOf("TOTP") != -1;
    var includeSMS = usc_enabledMethods.indexOf("SMSOTP") != -1;
    var includeEmail = usc_enabledMethods.indexOf("EmailOTP") != -1;
    var includeVerify = usc_enabledMethods.indexOf("Verify") != -1;
    if (!includeTOTP) {
        document.querySelector('[next-target="totp"]').style.visibility = "hidden";
    }
    if (!includeSMS) {
        document.querySelector('[data-target="section-sms"]').style.visibility = "hidden";
    }
    if (!includeEmail) {
        document.querySelector('[data-target="section-email"]').style.visibility = "hidden";
    }
    if (!includeVerify) {
        document.querySelector('[next-target="verify"]').style.visibility = "hidden";
    }
    if (!includeTOTP && !includeSMS && !includeVerify) {
        document.querySelector('[data-target="section-mobile-choose"]').style.visibility = "hidden";
    }

    var dropdownList = document.querySelector('.dropdown-list');
    for (var i = 0; i < countries.length; i++) {
        var entry = document.createElement('li');
        entry.textContent = countries[i];
        entry.onclick = function() {
            document.getElementById("countryDropdown").textContent = this.textContent;
            document.getElementById("countryCode").textContent = phoneCodes[this.textContent];
        };
        dropdownList.appendChild(entry);
    }

    document.querySelector('.overlay').addEventListener('click', function(event) {
        event.preventDefault();
        closeDialog();
    });

    usc_actionLocation = getJunctionName() + usc_action;
    usc_actionLocation = usc_actionLocation.replace("authsvc", "apiauthsvc");

    configureEvent('.sms-container input', '.sms-container .button-1');
    configureEvent('.email-container input', '.email-container .button-1');
    configureEvent('.sms-validate-container input', '.sms-validate-container .button-1');
    configureEvent('.email-validate-container input', '.email-validate-container .button-1');
    configureEvent('.totp-validate-container input', '.totp-validate-container .button-1');
}

function populateDevices() {
    if (usc_methods.length > 0 || usc_authenticators.length > 0) {
        document.getElementById("noDevicesContainer").classList.remove('all-device-containers-empty');
        document.getElementById("deviceContainer").classList.remove('hidden');
    } else {
        document.getElementById("noDevicesContainer").classList.add('all-device-containers-empty');
    }

    var deviceContainerDiv = document.getElementById("deviceContainer");
    for (var i = 0; i < usc_methods.length; i++) {
        var method = usc_methods[i];
        var id = method['id'];
        var creationDate = new Date(method['creationTime']);
        var type = method['type'];
        var enabled = method['enabled'];
        var enabledPretty = enabled ? ciMsg.enabled : ciMsg.disabled;
        var enablePretty = !enabled ? ciMsg.enable : ciMsg.disable;

        if (type != "signature") {
            var enabled = method['enabled'] ? ciMsg.enabled : ciMsg.disabled;

            var methodDiv = document.createElement('div');
            methodDiv.className = "sc-device";
            methodDiv.id = id;
            methodDiv.type = type;

            if (!enabled) {
                methodDiv.classList.add("device-deactivated");
            }

            var dropdownDiv = document.createElement('div');
            dropdownDiv.className = "sc-more-dropdown";
            var moreMenu = document.createElement('button');
            moreMenu.className = "more-menu";
            moreMenu.id = method.id;
            moreMenu.onclick = function() {
                if (this.parentNode.children[1].style.display == "block") {
                    this.parentNode.children[1].style.display = "none";
                } else {
                    this.parentNode.children[1].style.display = "block";
                }
            };
            dropdownDiv.appendChild(moreMenu);

            var dropdownList = document.createElement('ul');
            dropdownList.className = "dropdown-list";
            var remove = document.createElement('li');
            remove.id = method.id;
            remove.type = type;
            remove.textContent = ciMsg.remove;
            dropdownList.appendChild(remove);

            remove.onclick = function() {
                hideList();

                var data = {
                    "action": "remove",
                    "type": this.type,
                    "id": this.id
                };
                var deleteRequest = new XMLHttpRequest();
                deleteRequest.open("PUT", usc_actionLocation, true);
                deleteRequest.setRequestHeader("Accept", "application/json");
                deleteRequest.setRequestHeader("Content-Type", "application/json");

                deleteRequest.onreadystatechange = function() {
                    if (deleteRequest.readyState == 4) {
                        ajaxActive = false;
                        manualRequest = null;
                        manualData = null;
                        var json = null;
                        if (deleteRequest.responseText) {
                            try {
                                json = JSON.parse(deleteRequest.responseText);
                            } catch (e) {
                                // probably not JSON -- handle in else.
                            }
                        }
                        if (deleteRequest.status == 200 && json != null) {
                            if (json.location != null && json.location != "") {
                                usc_actionLocation = json.location;
                            }
                            var errorStr = null;
                            if (json.exceptionMsg != null && json.exceptionMsg != "") {
                                // An error was thrown!
                                errorStr = ciMsg.deleteFailed;
                            } else if (json.errorMessage != null && json.errorMessage != "") {
                                // An error was thrown!
                                errorStr = ciMsg.deleteFailed;
                            } else if (json.operation != null && json.operation != "") {
                                // WebSEAL is giving us a weird response.
                                errorStr = ciMsg.deleteFailed;
                            }
                            if (errorStr != null) {
                                showList();
                                notify(errorStr, true);
                            } else {
                                refreshList();
                            }
                        } else {
                            var errorStr = ciMsg.deleteFailedNoState;
                            if (json != null) {
                                if (json.location != null && json.location != "") {
                                    usc_actionLocation = json.location;
                                }
                                errorStr = ciMsg.deleteFailed;
                                if (json.error != null) {
                                    errorStr = json.error;
                                }
                            }
                            showList();
                            notify(errorStr, true);
                        }
                    }
                };

                if (ajaxTimer != null) {
                    window.clearTimeout(ajaxTimer);
                }
                if (!ajaxActive) {
                    ajaxActive = true;
                    deleteRequest.send(JSON.stringify(data));
                } else {
                    manualRequest = deleteRequest;
                    manualData = JSON.stringify(data);
                }
            };

            dropdownDiv.appendChild(dropdownList);
            methodDiv.appendChild(dropdownDiv);

            var illustrationDiv = document.createElement('div');
            illustrationDiv.className = "sc-device-illustration";
            var image = document.createElement('img');
            image.src = getJunctionName() + "/sps/static/design_images/" + type + ".svg";
            image.alt = "illustration";
            illustrationDiv.appendChild(image);
            methodDiv.appendChild(illustrationDiv);

            var infoDiv = document.createElement('div');
            infoDiv.className = "sc-device-info";
            var infoTitleDiv = document.createElement('div');
            infoTitleDiv.className = "sc-device-title";
            infoTitleDiv.textContent = ciMsg[type];
            infoDiv.appendChild(infoTitleDiv);
            if (type == "smsotp" || type == "emailotp") {
                var extraInfo = "";
                if (type == "emailotp") {
                    extraInfo = method['attributes'].emailAddress;
                } else if (type == "smsotp") {
                    extraInfo = method['attributes'].phoneNumber;
                }
                extraInfo = extraInfo.replace(/\*/g, "•");
                var deviceInfoDiv = document.createElement('div');
                deviceInfoDiv.className = "sc-device-type";
                deviceInfoDiv.textContent = extraInfo;
                infoDiv.appendChild(deviceInfoDiv);
            }
            var enabledTitleDiv = document.createElement('div');
            enabledTitleDiv.className = "sc-device-enabled";
            enabledTitleDiv.textContent = enabled;
            infoDiv.appendChild(enabledTitleDiv);
            methodDiv.appendChild(infoDiv);
            deviceContainerDiv.appendChild(methodDiv);
        }
    }

    for (var i = 0; i < usc_authenticators.length; i++) {
        var authenticator = usc_authenticators[i];
        var id = authenticator['id'];
        var type = "verify";
        var enabled = authenticator['enabled'];
        var creationDate = new Date(authenticator['creationTime']);
        var enabledPretty = enabled ? ciMsg.enabled : ciMsg.disabled;
        var enablePretty = !enabled ? ciMsg.enable : ciMsg.disable;
        var imgsrc = getJunctionName() + "/sps/static/design_images/fingerprint.svg";

        var methodDiv = document.createElement('div');
        methodDiv.className = "sc-device";
        methodDiv.id = id;
        methodDiv.type = type;

        if (!enabled) {
            methodDiv.classList.add("device-deactivated");
        }

        var dropdownDiv = document.createElement('div');
        dropdownDiv.className = "sc-more-dropdown";
        var moreMenu = document.createElement('button');
        moreMenu.className = "more-menu";
        moreMenu.id = id;
        moreMenu.onclick = function() {
            if (this.parentNode.children[1].style.display == "block") {
                this.parentNode.children[1].style.display = "none";
            } else {
                this.parentNode.children[1].style.display = "block";
            }
        };

        dropdownDiv.appendChild(moreMenu);
        var dropdownList = document.createElement('ul');
        dropdownList.className = "dropdown-list";
        var enable = document.createElement('li');
        enable.id = id;
        enable.type = type;
        enable.enabled = enabled;
        enable.textContent = enablePretty;
        dropdownList.appendChild(enable);
        var remove = document.createElement('li');
        remove.id = id;
        remove.type = type;
        remove.textContent = ciMsg.remove;
        dropdownList.appendChild(remove);

        enable.onclick = function() {
            var data = {
                "action": "update",
                "type": this.type,
                "id": this.id,
                enabled: !this.enabled
            };
            var updateRequest = new XMLHttpRequest();
            updateRequest.open("PUT", usc_actionLocation, true);
            updateRequest.setRequestHeader("Accept", "application/json");
            updateRequest.setRequestHeader("Content-Type", "application/json");

            updateRequest.onreadystatechange = function() {
                if (updateRequest.readyState == 4) {
                    ajaxActive = false;
                    manualRequest = null;
                    manualData = null;
                    var json = null;
                    if (updateRequest.responseText) {
                        try {
                            json = JSON.parse(updateRequest.responseText);
                        } catch (e) {
                            // probably not JSON -- handle in else.
                        }
                    }
                    if (updateRequest.status == 200 && json != null) {
                        if (json.location != null && json.location != "") {
                            usc_actionLocation = json.location;
                        }
                        var errorStr = null;
                        if (json.exceptionMsg != null && json.exceptionMsg != "") {
                            // An error was thrown!
                            errorStr = ciMsg.updateFailed;
                        } else if (json.errorMessage != null && json.errorMessage != "") {
                            // An error was thrown!
                            errorStr = ciMsg.updateFailed;
                        } else if (json.operation != null && json.operation != "") {
                            // WebSEAL is giving us a weird response.
                            errorStr = ciMsg.updateFailed;
                        }
                        if (errorStr != null) {
                            showList();
                            notify(errorStr, true);
                        } else {
                            refreshList();
                        }
                    } else {
                        var errorStr = ciMsg.updateFailedNoState;
                        if (json != null) {
                            if (json.location != null && json.location != "") {
                                usc_actionLocation = json.location;
                            }
                            errorStr = ciMsg.updateFailed;
                            if (json.error != null) {
                                errorStr = json.error;
                            }
                        }
                        showList();
                        notify(errorStr, true);
                    }
                }
            };
            if (ajaxTimer != null) {
                window.clearTimeout(ajaxTimer);
            }
            if (!ajaxActive) {
                ajaxActive = true;
                updateRequest.send(JSON.stringify(data));
            } else {
                manualRequest = updateRequest;
                manualData = JSON.stringify(data);
            }
        };
        remove.onclick = function() {
            hideList();

            var data = {
                "action": "remove",
                "type": this.type,
                "id": this.id
            };
            var deleteRequest = new XMLHttpRequest();
            deleteRequest.open("PUT", usc_actionLocation, true);
            deleteRequest.setRequestHeader("Accept", "application/json");
            deleteRequest.setRequestHeader("Content-Type", "application/json");

            deleteRequest.onreadystatechange = function() {
                if (deleteRequest.readyState == 4) {
                    ajaxActive = false;
                    manualRequest = null;
                    manualData = null;
                    var json = null;
                    if (deleteRequest.responseText) {
                        try {
                            json = JSON.parse(deleteRequest.responseText);
                        } catch (e) {
                            // probably not JSON -- handle in else.
                        }
                    }
                    if (deleteRequest.status == 200 && json != null) {
                        if (json.location != null && json.location != "") {
                            usc_actionLocation = json.location;
                        }
                        var errorStr = null;
                        if (json.exceptionMsg != null && json.exceptionMsg != "") {
                            // An error was thrown!
                            errorStr = ciMsg.deleteFailed;
                        } else if (json.errorMessage != null && json.errorMessage != "") {
                            // An error was thrown!
                            errorStr = ciMsg.deleteFailed;
                        } else if (json.operation != null && json.operation != "") {
                            // WebSEAL is giving us a weird response.
                            errorStr = ciMsg.updateFailed;
                        }
                        if (errorStr != null) {
                            showList();
                            notify(errorStr, true);
                        } else {
                            refreshList();
                        }
                    } else {
                        var errorStr = ciMsg.deleteFailedNoState;
                        if (json != null) {
                            if (json.location != null && json.location != "") {
                                usc_actionLocation = json.location;
                            }
                            errorStr = ciMsg.deleteFailed;
                            if (json.error != null) {
                                errorStr = json.error;
                            }
                        }
                        showList();
                        notify(errorStr, true);
                    }
                }
            };

            if (ajaxTimer != null) {
                window.clearTimeout(ajaxTimer);
            }
            if (!ajaxActive) {
                ajaxActive = true;
                deleteRequest.send(JSON.stringify(data));
            } else {
                manualRequest = deleteRequest;
                manualData = JSON.stringify(data);
            }
        };
        dropdownDiv.appendChild(dropdownList);
        methodDiv.appendChild(dropdownDiv);

        var illustrationDiv = document.createElement('div');
        illustrationDiv.className = "sc-device-illustration";
        var image = document.createElement('img');
        image.src = imgsrc;
        image.alt = "illustration";
        illustrationDiv.appendChild(image);
        methodDiv.appendChild(illustrationDiv);

        var infoDiv = document.createElement('div');
        infoDiv.className = "sc-device-info";
        var infoTitleDiv = document.createElement('div');
        infoTitleDiv.className = "sc-device-title";
        infoTitleDiv.textContent = ciMsg.ibmVerify;
        infoDiv.appendChild(infoTitleDiv);
        var deviceInfoDiv = document.createElement('div');
        deviceInfoDiv.className = "sc-device-type";
        deviceInfoDiv.textContent = authenticator.attributes.deviceName + ' (' + authenticator.attributes.deviceType + " " + (authenticator.attributes.deviceType.startsWith("i") ? "iOS " : "Android ") + authenticator.attributes.osVersion + ')';
        infoDiv.appendChild(deviceInfoDiv);
        var enabledTitleDiv = document.createElement('div');
        enabledTitleDiv.className = "sc-device-enabled";
        enabledTitleDiv.textContent = enabledPretty;
        infoDiv.appendChild(enabledTitleDiv);
        methodDiv.appendChild(infoDiv);
        deviceContainerDiv.insertBefore(methodDiv, deviceContainerDiv.childNodes[0]);
    }

    document.addEventListener('click', function(event) {
        if (!event.target.classList.contains('more-menu')) {
            var cardMenus = document.querySelectorAll('.dropdown-list');
            for (var i = 0; i < cardMenus.length; i++) {
                cardMenus[i].style.display = '';
            }
        }
    });
}

function refreshList() {
    hideList();

    var data = {
        "action": "initiate"
    };
    var request = new XMLHttpRequest();
    request.open("PUT", usc_actionLocation, true);
    request.setRequestHeader("Accept", "application/json");
    request.setRequestHeader("Content-Type", "application/json");

    request.onreadystatechange = function() {
        if (request.readyState == 4) {
            ajaxActive = false;
            manualRequest = null;
            manualData = null;
            var json = null;
            if (request.responseText) {
                try {
                    json = JSON.parse(request.responseText);
                } catch (e) {
                    // probably not JSON -- handle in else.
                }
            }
            if (request.status == 200 && json != null && json.methods != null) {
                if (json.location != null && json.location != "") {
                    usc_actionLocation = json.location;
                }
                usc_methods = json.methods;
                usc_authenticators = json.authenticators;
                document.getElementById("authenticatorsTotal").textContent = json.authenticators.length;
                document.getElementById("methodsTotal").textContent = json.methods.length;

                var deviceContainerDiv = document.getElementById("deviceContainer");
                while (deviceContainerDiv.lastChild) {
                    deviceContainerDiv.removeChild(deviceContainerDiv.lastChild);
                }
                populateDevices();
                showList();
            } else {
                var errorStr = ciMsg.refreshFailedNoState;
                if (json != null) {
                    if (json.location != null && json.location != "") {
                        usc_actionLocation = json.location;
                    }
                    errorStr = ciMsg.refreshFailed;
                    if (json.error != null) {
                        errorStr = json.error;
                    }
                }
                showList();
                notify(errorStr, true);
            }
        }
    };

    if (ajaxTimer != null) {
        window.clearTimeout(ajaxTimer);
    }
    if (!ajaxActive) {
        ajaxActive = true;
        request.send(JSON.stringify(data));
    } else {
        manualRequest = request;
        manualData = JSON.stringify(data);
    }
}

function hideList() {
    var deviceContainerDiv = document.getElementById("deviceContainer");
    var loader = document.querySelector(".wrapper .loader");
    deviceContainerDiv.classList.add('hidden');
    document.getElementById("noDevicesContainer").classList.remove('all-device-containers-empty');
    loader.classList.remove('hidden');
}

function showList() {
    var deviceContainerDiv = document.getElementById("deviceContainer");
    var loader = document.querySelector(".wrapper .loader");
    deviceContainerDiv.classList.remove('hidden');
    loader.classList.add('hidden');
}

function launchRegisterDialog() {
    var incomingSection = document.querySelector('[data-name="section-welcome"]');

    incomingSection.style.left = '';
    incomingSection.classList.add('dialog-content--visible');

    document.querySelector('.dialog-back').style.display = 'none';
    document.querySelector('.dialog-close').classList.add('dialog-close--dark');
    document.querySelector('.dialog-close').style.display = 'block';

    document.querySelector('.overlay').classList.remove('close-overlay');
    dialogWindow = document.querySelector('.dialog-window').classList.remove('close-window');
    document.querySelector('#dialog').style.display = 'block';

    incomingSection.querySelector('.button-1').focus();
}

function learnMore() {
    var welcomeSection = document.querySelector('[data-name="section-welcome"]');
    document.querySelector('.dialog-back').style.display = 'block';
    welcomeSection.classList.add('dialog-content--more-info-visible');
    document.querySelector('.dialog-close').classList.remove('dialog-close--dark');
}

function dialogBack() {
    var welcomeSection = document.querySelector('[data-name="section-welcome"]');
    if (welcomeSection && welcomeSection.classList.contains('dialog-content--more-info-visible')) {
        welcomeSection.classList.remove('dialog-content--more-info-visible');
        document.querySelector('.dialog-back').style.display = 'none';
        document.querySelector('.dialog-close').classList.add('dialog-close--dark');
        return;
    }

    var outgoingSection = document.querySelector('.dialog-content--visible');
    var incomingSection;

    if (outgoingSection.getAttribute('data-name') == "section-mobile-choose") {
        incomingSection = document.querySelector('[data-name="section-welcome"]');
    } else if (outgoingSection.getAttribute('data-name') == "section-email") {
        incomingSection = document.querySelector('[data-name="section-welcome"]');
        outgoingSection.querySelector('#emailOtpDelivery').value = "";
    } else if (outgoingSection.getAttribute('data-name') == "section-download") {
        incomingSection = document.querySelector('[data-name="section-mobile-choose"]');
    } else if (outgoingSection.getAttribute('data-name') == "section-connectaccount") {
        incomingSection = document.querySelector('[data-name="section-download"]');
    } else if (outgoingSection.getAttribute('data-name') == "section-sms") {
        incomingSection = document.querySelector('[data-name="section-mobile-choose"]');
        outgoingSection.querySelector('#smsOtpDelivery').value = "";
        outgoingSection.querySelector('#countryCode').textContent = "+1";
        outgoingSection.querySelector('#countryDropdown').textContent = ciMsg.country;
    }

    var incomingSectionRightPane = incomingSection.querySelector('.layout-right');
    var incomingSectionLeftPane = incomingSection.querySelector('.layout-left');
    var outgoingSectionRightPane = outgoingSection.querySelector('.layout-right');
    var outgoingSectionLeftPane = outgoingSection.querySelector('.layout-left');

    var incomingSectionRightIllustration = incomingSection.querySelector('.example-animation');
    var outgoingSectionRightIllustration = outgoingSection.querySelector('.example-animation');

    if (outgoingSection && incomingSection.querySelector('.layout-left') && outgoingSection.querySelector('.layout-left')) {
        incomingSection.style.left = '';

        if (outgoingSectionRightIllustration != null) {
            outgoingSectionRightIllustration.style.transition = 'all 300ms cubic-bezier(.85, 0, .9, .4)';
            outgoingSectionRightIllustration.classList.add('example-animation--hidden');
        }

        incomingSectionLeftPane.classList.remove('layout-left--hidden');
        incomingSectionRightPane.classList.add('layout-right--hidden');

        setTimeout(function() {
            incomingSection.classList.remove('dialog-content--hidden');
            incomingSection.classList.add('dialog-content--visible');
        }, 300);

        setTimeout(function() {
            if (incomingSectionRightIllustration != null) {
                incomingSectionRightIllustration.style.transition = 'none'
                incomingSectionRightIllustration.classList.remove('example-animation--hidden');
            }
            incomingSectionRightPane.style.transition = 'opacity 100ms cubic-bezier(.1, .6, .15, 1)';
            incomingSectionRightPane.classList.remove('layout-right--hidden');
        }, 300)

        setTimeout(function() {
            incomingSectionRightPane.style.transition = '';

            outgoingSection.classList.remove('dialog-content--visible');
            outgoingSection.style.transition = '';

            outgoingSectionRightPane.classList.remove('layout-right--hidden');
            outgoingSectionRightPane.style.transition = '';

            if (outgoingSectionRightIllustration != null) {
                outgoingSectionRightIllustration.classList.remove('example-animation--hidden');
                outgoingSectionRightIllustration.style.transition = '';
            }

            outgoingSectionLeftPane.classList.remove('layout-left--hidden');
            outgoingSectionLeftPane.style.transition = '';
        }, 500);

    } else {
        incomingSection.style.left = '';
        incomingSection.classList.remove('dialog-content--hidden');
        incomingSection.classList.add('dialog-content--visible');
        outgoingSection.classList.remove('dialog-content--visible');
    }

    if (incomingSection.getAttribute('data-name') === 'section-welcome' ||
        incomingSection.getAttribute('data-name') === 'section-connectaccount') {
        document.querySelector('.dialog-back').style.display = 'none';
    } else {
        document.querySelector('.dialog-back').style.display = 'block';
    }

    if (incomingSection.querySelector('.small-layout') || incomingSection.querySelector('.simple-container')) {
        document.querySelector('.dialog-close').classList.add('dialog-close--dark');
    } else {
        document.querySelector('.dialog-close').classList.remove('dialog-close--dark');
    }

    if (incomingSection.getAttribute('data-name') === 'section-complete') {
        document.querySelector('.dialog-close').style.display = 'none';
        document.querySelector('.dialog-back').style.display = 'none';
    } else {
        document.querySelector('.dialog-close').style.display = 'block';
    }

    if (incomingSection.getAttribute('data-name') === 'section-sms' ||
        incomingSection.getAttribute('data-name') === 'section-email' ||
        incomingSection.getAttribute('data-name') === 'section-sms-validation' ||
        incomingSection.getAttribute('data-name') === 'section-email-validation' ||
        incomingSection.getAttribute('data-name') === 'section-totp-validation') {
        if (incomingSection.querySelector('.textbox-right')) {
            setTimeout(function() {
                incomingSection.querySelector('.textbox-right').focus();
            }, 300);
        } else if (incomingSection.querySelector('.ci-input')) {
            setTimeout(function() {
                incomingSection.querySelector('.ci-input').focus();
            }, 300);
        } else if (incomingSection.querySelector('.button-1')) {
            setTimeout(function() {
                incomingSection.querySelector('.button-1').focus();
            }, 300);
        }
    } else {
        if (incomingSection.querySelector('.button-1')) {
            setTimeout(function() {
                incomingSection.querySelector('.button-1').focus();
            }, 300);
        }
    }
}

function showContentSection(selection) {
    var incomingSection = document.querySelector('[data-name="' + selection.getAttribute('data-target') + '"]');
    var outgoingSection = document.querySelector('.dialog-content--visible');

    if (outgoingSection.getAttribute('data-name') == "section-mobile-choose") {
        incomingSection.setAttribute('next-target', selection.getAttribute('next-target'));
    }
    if (outgoingSection.getAttribute('data-name') == "section-download") {
        incomingSection.setAttribute('next-target', outgoingSection.getAttribute('next-target'));
    }

    if (outgoingSection && incomingSection.querySelector('.layout-left') && outgoingSection.querySelector('.layout-left')) {
        var incomingSectionRightPane = incomingSection.querySelector('.layout-right');
        var incomingSectionLeftPane = incomingSection.querySelector('.layout-left');
        var outgoingSectionRightPane = outgoingSection.querySelector('.layout-right');
        var outgoingSectionLeftPane = outgoingSection.querySelector('.layout-left');

        outgoingSectionLeftPane.classList.add('layout-left--hidden');
        incomingSection.style.left = '';
        incomingSection.classList.add('dialog-content--visible');

        var incomingSectionRightIllustration = incomingSection.querySelector('.example-animation');
        var outgoingSectionRightIllustration = outgoingSection.querySelector('.example-animation');
        if (incomingSectionRightIllustration != null) {
            incomingSectionRightIllustration.classList.add('example-animation--hidden');
            setTimeout(function() {
                incomingSectionRightIllustration.style.transition = 'all 300ms cubic-bezier(.1, .6, .15, 1)';
                incomingSectionRightIllustration.classList.remove('example-animation--hidden');
                incomingSectionRightIllustration.style.transition = '';
            }, 300)
        }
        if (outgoingSectionRightIllustration != null) {
            outgoingSectionRightIllustration.classList.add('example-animation--hidden');
        }

        setTimeout(function() {
            outgoingSection.classList.remove('dialog-content--visible');
        }, 300)

        setTimeout(function() {
            outgoingSectionLeftPane.classList.remove('layout-left--hidden');
            outgoingSection.classList.add('dialog-content--hidden');
            outgoingSection.style.left = '-100%'
        }, 600);

    } else {
        if (outgoingSection) {
            outgoingSection.classList.remove('dialog-content--visible');
            outgoingSection.classList.add('dialog-content--hidden');
            setTimeout(function() {
                outgoingSection.style.left = '-100%';
            }, 300);
        }
        incomingSection.style.left = '';
        incomingSection.classList.add('dialog-content--visible');
    }

    if (incomingSection.getAttribute('data-name') === 'section-welcome' ||
        incomingSection.getAttribute('data-name') === 'section-connectaccount') {
        document.querySelector('.dialog-back').style.display = 'none';
    } else {
        document.querySelector('.dialog-back').style.display = 'block';
    }

    if (incomingSection.querySelector('.small-layout') || incomingSection.querySelector('.simple-container')) {
        document.querySelector('.dialog-close').classList.add('dialog-close--dark');
    } else {
        document.querySelector('.dialog-close').classList.remove('dialog-close--dark');
    }

    if (incomingSection.getAttribute('data-name') === 'section-complete' ||
        incomingSection.getAttribute('data-name') === 'section-sms-validation' ||
        incomingSection.getAttribute('data-name') === 'section-email-validation' ||
        incomingSection.getAttribute('data-name') === 'section-totp-validation') {
        document.querySelector('.dialog-close').style.display = 'none';
        document.querySelector('.dialog-back').style.display = 'none';
    } else {
        document.querySelector('.dialog-close').style.display = 'block';
    }

    if (incomingSection.getAttribute('data-name') === 'section-sms' ||
        incomingSection.getAttribute('data-name') === 'section-email' ||
        incomingSection.getAttribute('data-name') === 'section-sms-validation' ||
        incomingSection.getAttribute('data-name') === 'section-email-validation' ||
        incomingSection.getAttribute('data-name') === 'section-totp-validation') {
        if (incomingSection.querySelector('.textbox-right')) {
            setTimeout(function() {
                incomingSection.querySelector('.textbox-right').focus();
            }, 300);
        } else if (incomingSection.querySelector('.ci-input')) {
            setTimeout(function() {
                incomingSection.querySelector('.ci-input').focus();
            }, 300);
        } else if (incomingSection.querySelector('.button-1')) {
            setTimeout(function() {
                incomingSection.querySelector('.button-1').focus();
            }, 300);
        }
    } else {
        if (incomingSection.querySelector('.button-1')) {
            setTimeout(function() {
                incomingSection.querySelector('.button-1').focus();
            }, 300);
        }
    }
}

function closeDialog() {
    resetQRCode();

    if (document.querySelector('.overlay') != null) {
        document.querySelector('.overlay').classList.add('close-overlay');
    }
    if (document.querySelector('.dialog-window') != null) {
        document.querySelector('.dialog-window').classList.add('close-window');
    }

    setTimeout(function() {
        document.querySelector('#dialog').style.display = 'none';
    }, 250);

    var hiddenSections = document.querySelectorAll('.dialog-content--hidden');
    var visibleSections = document.querySelectorAll('.dialog-content--visible');
    var hiddenAnimations = document.querySelectorAll('.example-animation--hidden');
    var visibleAnimations = document.querySelectorAll('.example-animation--visible');

    Array.prototype.forEach.call(hiddenSections, function(hiddenSection) {
        hiddenSection.classList.remove('dialog-content--hidden');
        hiddenSection.removeAttribute('style');
    });

    Array.prototype.forEach.call(visibleSections, function(visibleSection) {
        visibleSection.classList.remove('dialog-content--visible');
        visibleSection.removeAttribute('style');
    });

    Array.prototype.forEach.call(hiddenAnimations, function(hiddenAnimation) {
        hiddenAnimation.classList.remove('example-animation--hidden');
    });

    Array.prototype.forEach.call(visibleAnimations, function(visibleAnimation) {
        visibleAnimation.classList.remove('example-animation--visible');
    });

    document.querySelector('.email-container').classList.remove('enrollment-failed');
    document.querySelector('.sms-container').classList.remove('enrollment-failed');
    document.querySelector('.email-validate-container').classList.remove('validation-failed');
    document.querySelector('.sms-validate-container').classList.remove('validation-failed');
    document.querySelector('.totp-validate-container').classList.remove('validation-failed');

    document.querySelector('.sms-container #smsOtpDelivery').value = "";
    document.querySelector('.sms-container #countryCode').textContent = "+1";
    document.querySelector('.sms-container #countryDropdown').textContent = ciMsg.country;
    document.querySelector('.email-container #emailOtpDelivery').value = "";

    if (refreshRequired) {
        refreshList();
        refreshRequired = false;
    }
    pollCount = 0;
}

var countries = [ciMsg.AD, ciMsg.AT, ciMsg.AU, ciMsg.BE, ciMsg.BM, ciMsg.CA, ciMsg.CY, ciMsg.CZ, ciMsg.DK, ciMsg.EE, ciMsg.FO, ciMsg.FI, ciMsg.FR, ciMsg.DE, ciMsg.GR, ciMsg.GL, ciMsg.HK, ciMsg.IS, ciMsg.IN, ciMsg.IE, ciMsg.IL, ciMsg.IT, ciMsg.JP, ciMsg.LI, ciMsg.LU, ciMsg.MT, ciMsg.MC, ciMsg.NL, ciMsg.NZ, ciMsg.NO, ciMsg.PH, ciMsg.PL, ciMsg.PT, ciMsg.SM, ciMsg.SA, ciMsg.SG, ciMsg.SK, ciMsg.SI, ciMsg.ES, ciMsg.SE, ciMsg.CH, ciMsg.TH, ciMsg.AE, ciMsg.GB, ciMsg.US];
//["Andorra","Austria","Australia","Belgium","Bermuda","Canada","Cyprus","Czech Republic","Denmark","Estonia","Faroe Islands","Finland","France","Germany","Greece","Greenland","Hong Kong","Iceland","India","Ireland","Israel","Italy","Japan","Liechtenstein","Luxembourg","Malta","Monaco","Netherlands","New Zealand","Norway","Philippines","Poland","Portugal","San Marino","Saudi Arabia","Singapore","Slovakia","Slovenia","Spain","Sweden","Switzerland","Thailand","United Arab Emirates","United Kingdom","United States"];
var phoneCodes = {}; phoneCodes[ciMsg.AD] = "+376"; phoneCodes[ciMsg.AT] = "+43"; phoneCodes[ciMsg.AU] = "+61"; phoneCodes[ciMsg.BE] = "+32"; phoneCodes[ciMsg.BM] = "+809"; phoneCodes[ciMsg.CA] = "+1"; phoneCodes[ciMsg.CY] = "+357"; phoneCodes[ciMsg.CZ] = "+420"; phoneCodes[ciMsg.DK] = "+45"; phoneCodes[ciMsg.EE] = "+372"; phoneCodes[ciMsg.FO] = "+298"; phoneCodes[ciMsg.FI] = "+358"; phoneCodes[ciMsg.FR] = "+33"; phoneCodes[ciMsg.DE] = "+49"; phoneCodes[ciMsg.GR] = "+30"; phoneCodes[ciMsg.GL] = "+299"; phoneCodes[ciMsg.HK] = "+852"; phoneCodes[ciMsg.IS] = "+354"; phoneCodes[ciMsg.IN] = "+91"; phoneCodes[ciMsg.IE] = "+353"; phoneCodes[ciMsg.IL] = "+972"; phoneCodes[ciMsg.IT] = "+39"; phoneCodes[ciMsg.JP] = "+81"; phoneCodes[ciMsg.LI] = "+423"; phoneCodes[ciMsg.LU] = "+352"; phoneCodes[ciMsg.MT] = "+356"; phoneCodes[ciMsg.MC] = "+33"; phoneCodes[ciMsg.NL] = "+31"; phoneCodes[ciMsg.NZ] = "+64"; phoneCodes[ciMsg.NO] = "+47"; phoneCodes[ciMsg.PH] = "+63"; phoneCodes[ciMsg.PL] = "+48"; phoneCodes[ciMsg.PT] = "+351"; phoneCodes[ciMsg.SM] = "+378"; phoneCodes[ciMsg.SA] = "+966"; phoneCodes[ciMsg.SG] = "+65"; phoneCodes[ciMsg.SK] = "+421"; phoneCodes[ciMsg.SI] = "+386"; phoneCodes[ciMsg.ES] = "+34"; phoneCodes[ciMsg.SE] = "+46"; phoneCodes[ciMsg.CH] = "+41"; phoneCodes[ciMsg.TH] = "+66"; phoneCodes[ciMsg.AE] = "+971"; phoneCodes[ciMsg.GB] = "+44"; phoneCodes[ciMsg.US] = "+1";

function countryDropDown(button) {
    if (button.parentNode.children[1].style.display == "block") {
        button.parentNode.children[1].style.display = "none";
    } else {
        button.parentNode.children[1].style.display = "block";
    }
};

function registerAuthenticatorOrTOTP(button) {
    showContentSection(button)
    type = button.parentNode.parentNode.getAttribute('next-target');
    if (type == "verify") {
        data = {
            "action": "register",
            "type": "verify"
        };
        document.querySelector("[data-name=section-connectaccount] .button-1").classList.add("hidden");
        pollCount = 30;
    } else {
        data = {
            "action": "register",
            "type": "totp"
        };
        document.querySelector("[data-name=section-connectaccount] .button-1").classList.remove("hidden");
    }
    registerRequest = new XMLHttpRequest();
    registerRequest.onreadystatechange = processRegisterRequest;
    registerRequest.open("PUT", usc_actionLocation, true);
    registerRequest.setRequestHeader("Accept", "application/json");
    registerRequest.setRequestHeader("Content-Type", "application/json");
    if (ajaxTimer != null) {
        window.clearTimeout(ajaxTimer);
    }
    if (!ajaxActive) {
        ajaxActive = true;
        registerRequest.send(JSON.stringify(data));
    } else {
        manualRequest = registerRequest;
        manualData = JSON.stringify(data);
    }
}

function processRegisterRequest() {
    if (registerRequest.readyState == 4) {
        ajaxActive = false;
        manualRequest = null;
        manualData = null;
        var json = null;
        if (registerRequest.responseText) {
            try {
                json = JSON.parse(registerRequest.responseText);
            } catch (e) {
                // probably not JSON -- handle in else.
            }
        }
        if (registerRequest.status == 200 && json != null) {
            if (json.location != null && json.location != "") {
                usc_actionLocation = json.location;
            }
            if (json.exceptionMsg != null && json.exceptionMsg != "") {
                // Error state!
                displayQRCodeError(json.exceptionMsg);
            } else if (json.errorMessage != null && json.errorMessage != "") {
                // Error state!
                displayQRCodeError(json.errorMessage);
            } else if (json.operation != null && json.operation != "") {
                // WebSEAL is giving us a weird response.
                displayQRCodeError(json.errorMessage);
            } else {
                refreshRequired = true;
                if (json.qrCode) {
                    displayQRCode(json.qrCode);
                } else {
                    displayQRCode(json.attributes.qrCode);
                }
                if (type == "verify") {
                    ajaxTimer = setTimeout(pollEnrollment, 2000);
                }
            }
        } else {
            var errorStr = ciMsg.qrCodeError;
            if (json != null) {
                if (json.location != null && json.location != "") {
                    usc_actionLocation = json.location;
                }
                if (json.exceptionMsg != null && json.exceptionMsg != "") {
                    // Error state!
                    errorStr = json.exceptionMsg;
                } else if (json.errorMessage != null && json.errorMessage != "") {
                    // Error state!
                    errorStr = json.errorMessage;
                }
            }
            displayQRCodeError(errorStr);
        }
    }
}

var pollCount = 30;
var ajaxTimer = null; // points to the result of setTimeout, so that a pending poll can be canceled
var ajaxActive = false; // is an ajax operation to the apiauthsvc currently active
var manualRequest = null;
var manualData = null;

function pollEnrollment() {
    if (pollCount > 0) {
        ajaxActive = true;
        var data = {
            "action": "pollEnrollment"
        };
        var pollRequest = new XMLHttpRequest();
        pollRequest.onreadystatechange = function() {
            processPollRequest(pollRequest);
        };
        pollRequest.open("PUT", usc_actionLocation, true);
        pollRequest.setRequestHeader("Accept", "application/json");
        pollRequest.setRequestHeader("Content-Type", "application/json");
        pollRequest.send(JSON.stringify(data));
        pollCount--;
    }
}

function processPollRequest(request) {
    if (request.readyState == 4) {
        ajaxActive = false;
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
                usc_actionLocation = json.location;
            }
            if (json.status == "success") {
                closeDialog();
            } else if (json.status == "successWithTOTP") {
                if (document.getElementById("qrCode").classList.contains("hidden")) {
                    // There was an error fetching the qr code. Don't prompt
                    // for validation.
                    closeDialog();
                } else {
                    showContentSection(document.querySelector("[data-target='section-totp-validation']"));
                }
            } else if (json.status == "pending") {
                if (manualRequest == null && ajaxActive == false) {
                    ajaxTimer = setTimeout(pollEnrollment, 2000);
                }
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
                usc_actionLocation = json.location;
            }
        }

        // If a button was pressed while we were doing the last ajax operation,
        // act on it now
        if (manualRequest != null) {
            submitManualRequest();
        }
    }
}

function submitManualRequest() {
    ajaxActive = true;
    manualRequest.open("PUT", usc_actionLocation, true);
    manualRequest.setRequestHeader("Accept", "application/json");
    manualRequest.setRequestHeader("Content-Type", "application/json");
    manualRequest.send(manualData);
}

function displayQRCode(qrcode) {
    Array.prototype.forEach.call(document.querySelectorAll('.qr-img'), function(qrElement) {
        qrElement.src = "data:image/png;base64," + qrcode;
    });
    document.getElementById("qrCode").classList.remove('hidden');
    document.querySelector(".layout-right .loader").classList.add('hidden');
}

function displayQRCodeError(message) {
    Array.prototype.forEach.call(document.querySelectorAll('.qr-code-error'), function(error) {
        if (message.includes("CSIBN0019E") || message.includes("CSIAH0610E")) {
            error.querySelector('.scan b').textContent = ciMsg.qrCodeErrorAlreadyEnroll;
            error.querySelector('.sm').textContent = ciMsg.qrCodeErrorEnrollOnce;
        }
        error.classList.remove('hidden');
    });
    document.querySelector(".layout-right .loader").classList.add('hidden');
}

function resetQRCode(qrcode) {
    Array.prototype.forEach.call(document.querySelectorAll('.qr-img'), function(qrElement) {
        qrElement.src = "";
    });
    document.getElementById("qrCode").classList.add('hidden');
    document.querySelector(".layout-right .loader").classList.remove('hidden');
    Array.prototype.forEach.call(document.querySelectorAll('.qr-code-error'), function(error) {
        error.classList.add('hidden');
        error.querySelector('.scan b').textContent = ciMsg.qrCodeError;
        error.querySelector('.sm').textContent = ciMsg.qrCodeErrorTryLater;
    });
}

function closeOrTotpValidation(button) {
    var type = button.parentNode.parentNode.getAttribute('next-target');
    if (type == "verify") {
        closeDialog();
    } else {
        if (document.getElementById("qrCode").classList.contains("hidden")) {
            // There was an error fetching the qr code. Don't prompt
            // for validation.
            closeDialog();
        } else {
            var container = button.parentNode.parentNode;
            showContentSection(container.querySelector('.validation'));
        }
    }
}

function enrollSMSorEmail(type, idStr, button) {
    document.querySelector('.email-container').classList.remove('enrollment-failed');
    document.querySelector('.sms-container').classList.remove('enrollment-failed');

    var container = button.parentNode;
    var otpDeliveryInput = container.querySelector(idStr);
    var otpDelivery = otpDeliveryInput.value;

    if (checkValid(otpDeliveryInput, type)) {
        if (type == "smsotp") {
            otpDelivery = container.querySelector('#countryCode').textContent + otpDelivery;
        }
        var data = {
            "action": "register",
            "type": type,
            "otpDelivery": otpDelivery
        };

        var enrollRequest = new XMLHttpRequest();
        enrollRequest.open("PUT", usc_actionLocation, true);
        enrollRequest.setRequestHeader("Accept", "application/json");
        enrollRequest.setRequestHeader("Content-Type", "application/json");

        enrollRequest.onreadystatechange = function() {
            if (enrollRequest.readyState == 4) {
                removeLoading(container, children, container.querySelector('.loader'));

                var json = null;
                if (enrollRequest.responseText) {
                    try {
                        json = JSON.parse(enrollRequest.responseText);
                    } catch (e) {
                        // probably not JSON -- handle in else.
                    }
                }
                if (enrollRequest.status == 200 && json != null) {
                    if (json.location != null && json.location != "") {
                        usc_actionLocation = json.location;
                    }

                    if ((json.exceptionMsg != null && json.exceptionMsg != "") ||
                        (json.errorMessage != null && json.errorMessage != "") ||
                        (json.operation != null && json.operation != "")) {
                        // Error state!
                        container.classList.add('enrollment-failed');

                    } else {
                        // Success, continue.
                        refreshRequired = true;
                        container.querySelector(idStr).value = "";
                        if (type == "smsotp") {
                            container.querySelector('#countryCode').textContent = "+1";
                            container.querySelector('#countryDropdown').textContent = ciMsg.country;
                        }

                        if (json.validationRequired == "true") {
                            var section = document.querySelector('[data-name="' + container.querySelector(".validation").getAttribute("data-target") + '"]');
                            section.querySelector('#correlation').textContent = json.correlation + " -";;
                            showContentSection(container.querySelector('.validation'));
                        } else {
                            showContentSection(button);
                        }
                    }
                } else {
                    if (json != null && json.location != null && json.location != "") {
                        usc_actionLocation = json.location;
                    }
                    // Error state!
                    container.classList.add('enrollment-failed');
                }
            }
        };

        enrollRequest.send(JSON.stringify(data));

        children = [container.querySelector('input'), container.querySelector('.nav-sectionlink')];
        if (type == "smsotp") {
            children = [container.querySelector('#phoneDiv'), container.querySelector('.nav-sectionlink'), container.querySelector('.sc-more-dropdown')];
        }
        addLoading(container, children, container.querySelector('.loader'));
    }
}

function validateOtp(type, idStr, button) {
    var container = button.parentNode;
    var otpInput = container.querySelector(idStr);
    var otp = otpInput.value;

    if (checkValid(otpInput, "otp")) {
        var data = {
            "action": "validateOTP",
            "type": type,
            "otp": otp
        };
        var validateRequest = new XMLHttpRequest();
        validateRequest.open("PUT", usc_actionLocation, true);
        validateRequest.setRequestHeader("Accept", "application/json");
        validateRequest.setRequestHeader("Content-Type", "application/json");

        validateRequest.onreadystatechange = function() {
            if (validateRequest.readyState == 4) {
                removeLoading(container, children, container.children[2]);
                var json = null;
                if (validateRequest.responseText) {
                    try {
                        json = JSON.parse(validateRequest.responseText);
                    } catch (e) {
                        // probably not JSON -- handle in else.
                    }
                }
                if (validateRequest.status == 200 && json != null) {
                    if (json.location != null && json.location != "") {
                        usc_actionLocation = json.location;
                    }
                    container.querySelector(idStr).value = "";

                    if (json.status == "success") {
                        if (container.querySelector('#correlation') != null) {
                            container.querySelector('#correlation').textContent = "";
                        }
                        showContentSection(button);
                    } else {
                        container.classList.add('validation-failed');
                    }
                } else {
                    if (json != null && json.location != null && json.location != "") {
                        usc_actionLocation = json.location;
                    }
                    container.classList.add('validation-failed');
                }
            }
        };
        validateRequest.send(JSON.stringify(data));

        children = [container.children[0], container.children[1]];
        addLoading(container, children, container.children[2]);
    }
}

function checkValid(input, type) {
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
    if (type == "otp" || type == "smsotp") {
        input.parentNode.parentNode.querySelector('[data-target="section-complete"]').disabled = !valid;
        input.parentNode.parentNode.classList.remove('validation-failed');
        input.parentNode.parentNode.classList.remove('enrollment-failed');
    } else {
        input.parentNode.querySelector('[data-target="section-complete"]').disabled = !valid;
        input.parentNode.classList.remove('enrollment-failed');
    }

    return valid;
}

function addLoading(parent, children, loader) {
    parent.classList.add('no-after');
    for (var i = 0; i < children.length; i++) {
        children[i].classList.add('hidden');
    }
    loader.classList.remove('hidden');
}

function removeLoading(parent, children, loader) {
    parent.classList.remove('no-after');
    for (var i = 0; i < children.length; i++) {
        children[i].classList.remove('hidden');
    }
    loader.classList.add('hidden');
}

function notify(message, sticky) {
    var notificationRibbon = document.querySelectorAll('.intime-alert');

    for (var i = 0; i < notificationRibbon.length; i++) {
        var notificationText = notificationRibbon[i].querySelector('p');

        if (sticky == null) {
            notificationText.textContent = message;
            notificationRibbon[i].classList.add('intime-alert--visible');
            removeNotify(notificationRibbon[i]);
        } else {
            notificationText = notificationRibbon[notificationRibbon.length - 1].querySelector('p');
            notificationText.textContent = message;
            notificationText.innerHTML += ' <a href="#" id="remove-notify-on-click" >' + ciMsg.okGotIt + '</a>';
            notificationRibbon[notificationRibbon.length - 1].classList.add('intime-alert--visible');

            document.getElementById("remove-notify-on-click").addEventListener("click", function(event) {
                removeNotify(null, true)
                event.preventDefault(); // Prevent default action (a following a link)
            }, false);
        }
    }
}

function removeNotify(notificationRibbon, sticky) {
    if (sticky == null) {
        setTimeout(function() {
            notificationRibbon.classList.remove('intime-alert--visible');
        }, 3000);
    } else {
        var notificationRibbon = document.querySelectorAll('.intime-alert');
        for (var i = 0; i < notificationRibbon.length; i++) {
            notificationRibbon[i].classList.remove('intime-alert--visible');
        }
    }
}

function populateStrings() {
    document.title = ciMsg.userSelfCare;
    document.querySelector('.header h2').textContent = ciMsg.userSelfCare;
    document.querySelector('[data-name="section-welcome-authenticators"] .self-care-header h3').textContent = ciMsg.twoStepVerification;
    document.querySelector('[data-name="section-welcome-authenticators"] .self-care-header h1').textContent = ciMsg.myAuthenticators;
    document.querySelector('[data-name="section-welcome-authenticators"] .self-care-header .add-device').textContent = ciMsg.add;
    document.querySelector('[data-name="section-welcome"] h1#learn-more-title').textContent = ciMsg.whatIsTwoStep;

    document.querySelector('.user-card .profile .email span').textContent = ciMsg.emailColon;
    document.querySelector('.user-card .profile .username span').textContent = ciMsg.usernameColon;
    document.querySelectorAll('.user-card .profile .extra span')[0].textContent = ciMsg.deviceColon;
    document.querySelectorAll('.user-card .profile .extra span')[2].textContent = ciMsg.methodsColon;

    document.querySelectorAll('[data-name="section-welcome"] h2')[0].textContent = ciMsg.whyYouNeedThis;
    document.querySelectorAll('[data-name="section-welcome"] h2')[1].textContent = ciMsg.howItWorks;
    document.querySelectorAll('[data-name="section-welcome"] .unordered-list li')[0].textContent = ciMsg.reason1;
    document.querySelectorAll('[data-name="section-welcome"] .unordered-list li')[1].textContent = ciMsg.reason2;
    document.querySelectorAll('[data-name="section-welcome"] .unordered-list li')[2].textContent = ciMsg.reason3;
    document.querySelectorAll('[data-name="section-welcome"] .ordered-list li')[0].textContent = ciMsg.how1;
    document.querySelectorAll('[data-name="section-welcome"] .ordered-list li')[1].textContent = ciMsg.how2;
    document.querySelectorAll('[data-name="section-welcome"] .layout-large-left h3')[0].innerHTML = ciMsg.welcomeName + usc_name;
    document.querySelectorAll('[data-name="section-welcome"] .layout-large-left h1')[0].innerHTML = ciMsg.strengthenYourAccount;
    document.querySelectorAll('[data-name="section-welcome"] .layout-large-left .type-body-m')[0].textContent = ciMsg.accountDesc1;
    document.querySelectorAll('[data-name="section-welcome"] .layout-large-left .type-body-m')[1].innerHTML = ciMsg.accountDesc2;
    document.querySelector('.button-1.nav-sectionlink[data-target="section-mobile-choose"]').textContent = ciMsg.getStartedMobile;
    document.querySelector('.button-1.nav-sectionlink[data-target="section-email"]').textContent = ciMsg.getStartedEmail;
    document.querySelector('[data-name="section-welcome"] .learn-more-link').textContent = ciMsg.learnMore;

    document.querySelector('[data-name="section-mobile-choose"] h1').textContent = ciMsg.chooseMethod;
    document.querySelector('[data-name="section-mobile-choose"] .type-body-m').textContent = ciMsg.chooseDesc;
    document.querySelector('[data-name="section-mobile-choose"] [next-target="verify"]').textContent = ciMsg.mobilePush;
    document.querySelector('[data-name="section-mobile-choose"] [next-target="totp"]').textContent = ciMsg.totp;
    document.querySelector('[data-name="section-mobile-choose"] [data-target="section-sms"]').textContent = ciMsg.smsotp;

    document.querySelector('[data-name="section-download"] h1').textContent = ciMsg.downloadApp;
    document.querySelector('.download-app').alt = ciMsg.downloadApp;
    document.querySelectorAll('[data-name="section-download"] .ordered-list li')[0].innerHTML = ciMsg.launchAppStore;
    document.querySelectorAll('[data-name="section-download"] .ordered-list li')[1].textContent = ciMsg.searchForVerify;
    document.querySelectorAll('[data-name="section-download"] .ordered-list li')[2].textContent = ciMsg.install;
    document.querySelector('[data-target="section-connectaccount"]').textContent = ciMsg.nextStepConnectAccount;
    document.querySelector('[data-name="section-connectaccount"] h1').textContent = ciMsg.connectYourAccount;
    document.querySelector('[data-name="section-connectaccount"] .type-body-m').textContent = ciMsg.connectYourAccountDesc;
    document.querySelector('[data-name="section-connectaccount"] .ordered-list').children[0].textContent = ciMsg.launchIBMVerify;
    document.querySelector('[data-name="section-connectaccount"] .ordered-list').children[1].textContent = ciMsg.tapConnectAccount;
    document.querySelector('[data-name="section-connectaccount"] .ordered-list').children[2].textContent = ciMsg.scanQRCode;
    document.querySelector('[data-name="section-connectaccount"] .qr-code#qrCode .scan b').textContent = ciMsg.scanMe;
    document.querySelector('[data-name="section-connectaccount"] .qr-code#qrCode .sm').textContent = ciMsg.qrCodeDesc;
    document.querySelector('[data-name="section-connectaccount"] .button-1').textContent = ciMsg.finish;
    document.querySelectorAll('[data-name="section-connectaccount"] .qr-code-error .scan b')[0].textContent = ciMsg.qrCodeError;
    document.querySelectorAll('[data-name="section-connectaccount"] .qr-code-error .sm')[0].textContent = ciMsg.qrCodeErrorTryLater;
    document.querySelectorAll('[data-name="section-connectaccount"] .qr-code-error .scan b')[1].textContent = ciMsg.qrCodeError;
    document.querySelectorAll('[data-name="section-connectaccount"] .qr-code-error .sm')[1].textContent = ciMsg.qrCodeErrorTryLater;

    document.querySelector('[data-name="section-sms"] h1').textContent = ciMsg.enterMobile;
    document.querySelector('[data-name="section-sms"] #countryDropdown').textContent = ciMsg.country;
    document.querySelector('[data-name="section-sms"] .button-1').textContent = ciMsg.save;

    document.querySelector('[data-name="section-sms-validation"] h1').textContent = ciMsg.letsMakeSure;
    document.querySelector('[data-name="section-sms-validation"] .button-1').textContent = ciMsg.validate;

    document.querySelector('[data-name="section-email"] h1').textContent = ciMsg.enterEmail;
    document.querySelector('[data-name="section-email"] .button-1').textContent = ciMsg.save;

    document.querySelector('[data-name="section-email-validation"] h1').textContent = ciMsg.letsMakeSure;
    document.querySelector('[data-name="section-email-validation"] .button-1').textContent = ciMsg.validate;

    document.querySelector('[data-name="section-totp-validation"] h1').textContent = ciMsg.letsCheck;
    document.querySelector('[data-name="section-totp-validation"] .button-1').textContent = ciMsg.validate;

    document.querySelector('[data-name="section-complete"] h3').textContent = ciMsg.success;
    document.querySelector('[data-name="section-complete"] h1').textContent = ciMsg.otpReady;
    document.querySelector('[data-name="section-complete"] .type-body-m').textContent = ciMsg.moreSecure;
    document.querySelector('[data-name="section-complete"] .button-1').textContent = ciMsg.finish;
    document.querySelector('[data-name="section-complete"] .welcome-illustrations img').alt = ciMsg.ibmVerify;

    document.styleSheets[2].insertRule('.sms-container::after { content: "' + ciMsg.smsDesc + '"; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.email-container::after { content: "' + ciMsg.emailDesc + '"; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.sms-validate-container:after { content: "' + ciMsg.smsOTPDesc + '"; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.email-validate-container:after { content: "' + ciMsg.emailOTPDesc + '"; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.totp-validate-container:after { content: "' + ciMsg.totpDesc + '"; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.enrollment-failed:after { content: "' + ciMsg.enrollmentFailed + '" !important; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.validation-failed:after { content: "' + ciMsg.validationFailed + '" !important; }', document.styleSheets[2].cssRules.length);
    document.styleSheets[2].insertRule('.all-device-containers-empty:after { content: "' + ciMsg.noEnrollments + '" !important; }', document.styleSheets[0].cssRules.length);
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
