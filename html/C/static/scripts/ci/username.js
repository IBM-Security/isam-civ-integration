// Copyright contributors to the IBM Verify Identity Access and Verify SaaS Strong Authentication Integration project.
window.addEventListener('load', (event) => {
    startup();

    document.getElementById("username").addEventListener("input", function() {
        enableButton(this)
    });
    document.getElementById("submit_button").addEventListener("click", submit);
});

function populateStrings() {
    document.title = ciMsg.signIn;
    document.querySelector("h3").textContent = ciMsg.welcome;
    document.querySelector("h1").textContent = ciMsg.signIn;
    document.getElementById("submit_button").textContent = ciMsg.signIn;
    document.getElementById("instructions").textContent = ciMsg.usernameInstructions;
    document.getElementById("username").placeholder = ciMsg.username;
    document.querySelectorAll("p")[1].textContent = ciMsg.username;
}

function enableButton(text) {
    if (text.value != null && text.value != "" && text.validity.valid) {
        document.getElementById("submit_button").disabled = false;
    } else {
        document.getElementById("submit_button").disabled = true;
    }
}

function submit() {
    document.querySelector(".loader").classList.remove('hidden');
    document.querySelector(".welcome-illustrations .launch-animation").classList.add('hidden');
    document.getElementById("submitForm").username.value = document.getElementById("username").value;
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
}
