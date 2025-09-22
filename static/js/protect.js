// Disable right-click
document.addEventListener("contextmenu", function (e) {
    e.preventDefault();
    alert("Right click is disabled on this page.");
});

// Disable specific key combinations
document.addEventListener("keydown", function (e) {
    // F12
    if (e.key === "F12") {
        e.preventDefault();
    }
    // Ctrl+Shift+I or Ctrl+Shift+J or Ctrl+U
    if ((e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J")) || 
        (e.ctrlKey && e.key === "u")) {
        e.preventDefault();
    }
});