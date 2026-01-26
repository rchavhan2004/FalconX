function login() {
    let user = document.getElementById("username").value;
    let pass = document.getElementById("password").value;

    if (user === "admin" && pass === "admin") {
        window.location.href = "home.html";
    } else {
        alert("Invalid username or password");
    }
}

