document.addEventListener("DOMContentLoaded", function() {
    const alerts = document.querySelectorAll(".alert");
    setTimeout(() => {
        alerts.forEach(alert => {
            alert.style.display = "none";
        });
    }, 3000);
});
