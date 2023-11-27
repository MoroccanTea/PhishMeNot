// Display version - DISABLED TO BE USED LATED IN SETTINGS
/*document.addEventListener('DOMContentLoaded', function() {
    const manifestData = chrome.runtime.getManifest();
    const version = manifestData.version;
    document.getElementById('version').textContent = `PhishMeNot V.${version}`;
  });*/


// Login button
document.getElementsByClassName('g-sign-in-button')[0].addEventListener('click', function() {
  chrome.runtime.sendMessage({action: "login"});
});