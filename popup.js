document.addEventListener('DOMContentLoaded', function () {
  const scanButton = document.getElementById('scanButton');
  const urlInput = document.getElementById('urlInput');
  const scanResult = document.getElementById('scanResult');

  scanButton.addEventListener('click', function () {
    const url = urlInput.value.trim();
    if (url !== '') {
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        const activeTab = tabs[0];
        chrome.runtime.getBackgroundPage(function (backgroundPage) {
          backgroundPage.scanURLWithVirusTotal(url, activeTab.id, function (result) {
            scanResult.innerText = JSON.stringify(result, null, 2);
          });
        });
      });
    } else {
      scanResult.innerText = 'Please enter a URL.';
    }
  });
});
