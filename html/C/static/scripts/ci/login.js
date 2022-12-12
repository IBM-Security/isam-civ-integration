// Copyright contributors to the IBM Security Verify Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();
    document.getElementById("submit_button").addEventListener("click", submit);
    document.getElementById("username").addEventListener("input", enableButton);
    document.getElementById("password").addEventListener("input", enableButton);
});

function populateStrings() {
    document.title = ciMsg.signIn;
    document.querySelector("h3").textContent = ciMsg.welcome;
    document.querySelector("h1").textContent = ciMsg.signIn;
    document.getElementById("submit_button").textContent = ciMsg.signIn;
    document.getElementById("instructions").textContent = ciMsg.loginInstructions;
    document.getElementById("username").placeholder = ciMsg.username;
    document.getElementById("password").placeholder = ciMsg.password;
    document.querySelectorAll("p")[1].textContent = ciMsg.username;
    document.querySelectorAll("p")[2].textContent = ciMsg.password;
}

function enableButton() {
    var usernameInput = document.getElementById("username");
    var passwordInput = document.getElementById("password");

    if (usernameInput.value != null && usernameInput.value != "" && usernameInput.validity.valid &&
        passwordInput.value != null && passwordInput.value != "" && passwordInput.validity.valid) {
        document.getElementById("submit_button").disabled = false;
    } else {
        document.getElementById("submit_button").disabled = true;
    }
}

function submit() {
    document.querySelector(".loader").classList.remove('hidden');
    document.querySelector(".welcome-illustrations .launch-animation").classList.add('hidden');
    document.getElementById("submitForm").username.value = document.getElementById("username").value;
    document.getElementById("submitForm").password.value = document.getElementById("password").value;
    document.getElementById("submitForm").submit();
}

function startup() {
    populateStrings();

    var input = document.querySelector('#username');
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13
        if (event.keyCode === 13) {
            document.querySelector('#submit_button').click();
        }
    });
    var input = document.querySelector('#password');
    input.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Enter key is 13
        if (event.keyCode === 13) {
            document.querySelector('#submit_button').click();
        }
    });
}
