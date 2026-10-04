// =====================================================
// CYBERSHIELD HUB AUTHENTICATION GUARD
// =====================================================

function isAuthenticated() {
    return !!localStorage.getItem("token");
}

function requireAuth() {

    if (!isAuthenticated()) {

        const currentPage =
            window.location.pathname.split("/").pop();

        // Remember which protected page the user wanted
        if (currentPage && currentPage !== "login.html") {
            sessionStorage.setItem(
                "authRedirect",
                currentPage
            );
        }

        window.location.replace("login.html");

        return false;
    }

    return true;
}


// Run immediately
requireAuth();


// Handle browser back/forward cache
window.addEventListener("pageshow", () => {

    requireAuth();

});