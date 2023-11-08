// popup.js cheikh mbow pour le bouton popup
window.onload = function() {
    document.getElementById("button").onclick = function() {
        chrome.extension.sendMessage({
            type: "color-divs"
        });
    }
}