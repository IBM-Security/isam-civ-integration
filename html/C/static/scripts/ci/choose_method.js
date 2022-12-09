// Copyright contributors to the IBM Security Verify Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    populateStrings();
});

var scriptElem = document.getElementById("choose-method-tags");
var scriptJson = JSON.parse(scriptElem.textContent);

var cm_methods = scriptJson["authMethods"];
var cm_signature_methods = scriptJson["signatureMethods"];
var cm_transient_methods = scriptJson["transientMethods"];

function createGrid() {
    var method_container_div = document.getElementById("method-container");

    for (var i = 0; i < cm_methods.length; i++) {
        var method = cm_methods[i];

        var id = method['id'];
        var creationDate = new Date(method['creationTime']);

        var type = method['methodType'];
        var enabled = method['isEnabled'];

        if (type != "signature" && enabled) {
            var method_div = document.createElement('div');
            method_div.className = "method";
            method_div.id = id;
            method_div.type = type;
            method_div.tabIndex = 0;

            method_div.onclick = function() {
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

            var illustration_div = document.createElement('div');
            illustration_div.className = "method-illustration";
            var image = document.createElement('img');
            image.src = "static/design_images/" + type + ".svg";
            image.alt = "illustration";
            illustration_div.appendChild(image);

            method_div.appendChild(illustration_div);

            var info_div = document.createElement('div');
            info_div.className = "method-info";
            var info_title_div = document.createElement('div');
            info_title_div.className = "method-title";
            info_title_div.textContent = ciMsg[type];
            info_div.appendChild(info_title_div);

            method_div.appendChild(info_div);

            method_container_div.appendChild(method_div);
        }
    }

    for (var i = 0; i < cm_signature_methods.length; i++) {

        var signature_method = cm_signature_methods[i];
        var id = signature_method['id'];
        var authenticator = signature_method["_embedded"];
        var authenticatorId = authenticator['id'];

        var enabled = authenticator['enabled'];
        if (enabled) {
            var type = signature_method["methodType"];
            var subType = signature_method["subType"];

            var imgsrc = getJunctionName() + "/sps/static/design_images/" + subType + ".svg";
            if (subType == "eye" || subType == "iris" || subType == "retina") {
                imgsrc = getJunctionName() + "/sps/static/design_images/face.svg";
            }

            var method_div = document.createElement('div');
            method_div.className = "method";
            method_div.id = id;
            method_div.type = type;
            method_div.tabIndex = 0;

            method_div.onclick = function() {
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

            var illustration_div = document.createElement('div');
            illustration_div.className = "method-illustration";
            var image = document.createElement('img');
            image.src = imgsrc;
            image.alt = "illustration";
            illustration_div.appendChild(image);

            method_div.appendChild(illustration_div);

            var info_div = document.createElement('div');
            info_div.classList.add("method-info");
            info_div.classList.add("verify-method-info");
            var info_title_div = document.createElement('div');
            info_title_div.className = "method-title";
            info_title_div.textContent = ciMsg.ibmVerify;
            info_div.appendChild(info_title_div);
            var method_info_div = document.createElement('div');
            method_info_div.className = "sc-device-type";
            method_info_div.textContent = ciMsg[subType];
            info_div.appendChild(method_info_div);
            var device_info_div = document.createElement('div');
            device_info_div.className = "sc-device-type";
            device_info_div.textContent = authenticator.attributes.deviceName + ' (' + authenticator.attributes.deviceType + ')';
            info_div.appendChild(device_info_div);

            method_div.appendChild(info_div);

            method_container_div.insertBefore(method_div, method_container_div.childNodes[0]);
        }
    }

    for (var i = 0; i < cm_transient_methods.length; i++) {

        var transient_method = cm_transient_methods[i];

        var imgsrc = getJunctionName() + "/sps/static/design_images/emailotp.svg";
        if (transient_method == "transientsms") {
            imgsrc = getJunctionName() + "/sps/static/design_images/smsotp.svg";
        }

        var method_div = document.createElement('div');
        method_div.className = "method";
        method_div.type = transient_method;
        method_div.tabIndex = 0;

        method_div.onclick = function() {
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

        var illustration_div = document.createElement('div');
        illustration_div.className = "method-illustration";
        var image = document.createElement('img');
        image.src = imgsrc;
        image.alt = "illustration";
        illustration_div.appendChild(image);

        method_div.appendChild(illustration_div);

        var info_div = document.createElement('div');
        info_div.className = "method-info";
        var info_title_div = document.createElement('div');
        info_title_div.className = "method-title";
        info_title_div.textContent = ciMsg[transient_method];
        info_div.appendChild(info_title_div);

        method_div.appendChild(info_div);

        method_container_div.appendChild(method_div);
    }

    if (cm_methods.length == 0 && cm_signature_methods.length == 0 && cm_transient_methods.length == 0) {
        document.getElementsByClassName("empty-method-container")[0].classList.remove("hidden");
        document.getElementsByClassName("empty-method-container")[0].classList.add("all-device-containers-empty");

    }
}

function populateStrings() {
    document.title = ciMsg.authMethodSelection;
    document.getElementsByClassName("pageTitle")[0].textContent = ciMsg.authenticate;
    document.getElementsByClassName("empty-method-container")[0].textContent = ciMsg.nothingConnected;
}

function startup() {
    populateStrings();
    createGrid();
}
