function applyTheme() {

    const savedTheme =
        localStorage.getItem("theme");

    if (savedTheme === "light") {
        document.body.classList.add("light-mode");
    } else {
        document.body.classList.remove("light-mode");
    }
}

applyTheme();