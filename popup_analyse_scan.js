document.addEventListener('DOMContentLoaded', function() {
    const autoScanToggle = document.getElementById('autoScanToggle');
    autoScanToggle.addEventListener('change', function() {
      // Variable pour stocker l'état du scan automatique (par défaut, il est activé)
        const isAutoScanEnabled = autoScanToggle.checked;
      if (isAutoScanEnabled) {
        // Logique pour activer le scan automatique
        function enableAutoScan() {
            isAutoScanEnabled = true;
            console.log('Scan automatique activé');
          }
        console.log('Scan automatique activé');
      } else {
        // Logique pour désactiver le scan automatique
        function disableAutoScan() {
            isAutoScanEnabled = false;
            console.log('Scan automatique désactivé');
          }
        console.log('Scan automatique désactivé');
      }
    });
});

    // Écouteur d'événement pour détecter les messages depuis le popup
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'toggleAutoScan') {
      const isEnabled = request.isEnabled;
      if (isEnabled && !isAutoScanEnabled) {
        enableAutoScan();
      } else if (!isEnabled && isAutoScanEnabled) {
        disableAutoScan();
      }
    }
  });