// Display version
document.addEventListener('DOMContentLoaded', function() {
    const manifestData = chrome.runtime.getManifest();
    const version = manifestData.version;
    document.getElementById('version').textContent = `PhishMeNot V.${version}`;
  });

// Login button
document.getElementById('loginButton').addEventListener('click', function() {
  chrome.runtime.sendMessage({action: "login"});
});