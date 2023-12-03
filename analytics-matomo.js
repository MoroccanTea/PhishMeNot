const matomoUrl = "PhishMeNot-URL";


const siteId = "PhishMeNot-URL-ID";


function sendMatomoRequest(action, additionalParams = {}) {
  const matomoTrackerUrl = `${matomoUrl}matomo.php`;

  const trackingData = {
    idsite: siteId,
    rec: 1,
    url: window.location.href,
    action_name: action,
    ...additionalParams,
  };

  const queryParams = Object.entries(trackingData)
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join("&");

  const requestUrl = `${matomoTrackerUrl}?${queryParams}`;


  fetch(requestUrl, { method: "GET" });
}


sendMatomoRequest("Extension Load");


document.getElementById("button-id").addEventListener("click", function () {
  sendMatomoRequest("Button Click");
});


chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.action === "Custom Event") {
    sendMatomoRequest("Custom Event", { custom_param: request.data });
  }
});


chrome.storage.onChanged.addListener(function (changes, namespace) {
  sendMatomoRequest("Storage Change", { changed_items: JSON.stringify(changes) });
});


chrome.webRequest.onCompleted.addListener(function (details) {
  sendMatomoRequest("Web Request Completed", { url: details.url });
}, { urls: ["<all_urls>"] });


chrome.contextMenus.onClicked.addListener(function (info, tab) {
  sendMatomoRequest("Context Menu Click", { menu_item_id: info.menuItemId });
});


chrome.tabs.onActivated.addListener(function (activeInfo) {
  sendMatomoRequest("Tab Activated", { tab_id: activeInfo.tabId });
});

const matomoScript = document.createElement("script");
matomoScript.src = `${matomoUrl}matomo.js`;
matomoScript.type = "text/javascript";
document.head.appendChild(matomoScript);
