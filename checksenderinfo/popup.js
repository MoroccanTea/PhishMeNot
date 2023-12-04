document.addEventListener("DOMContentLoaded", function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      chrome.tabs.sendMessage(tabs[0].id, { action: "checkPhishing" }, function (response) {
        const popupMessage = document.getElementById("popup-message");
        popupMessage.textContent = response.message;
      });
    });
  });
  