"use strict";

// Fonction pour activer le scan automatique
function enableAutoScan() {
  // Votre logique pour activer le scan automatique ici
  console.log('Scan automatique activé');
} // Fonction pour désactiver le scan automatique


function disableAutoScan() {
  // Votre logique pour désactiver le scan automatique ici
  console.log('Scan automatique désactivé');
} // Écouteur d'événement pour détecter les changements depuis le popup


chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.action === 'toggleAutoScan') {
    var isAutoScanEnabled = request.isEnabled;

    if (isAutoScanEnabled) {
      enableAutoScan();
    } else {
      disableAutoScan();
    }
  }
});
document.addEventListener('DOMContentLoaded', function () {
  var autoScanToggle = document.getElementById('autoScanToggle');
  autoScanToggle.addEventListener('change', function () {
    var isEnabled = autoScanToggle.checked; // Envoi d'un message au script de fond pour activer ou désactiver le scan automatique

    chrome.runtime.sendMessage({
      action: 'toggleAutoScan',
      isEnabled: isEnabled
    });
  });
});
//# sourceMappingURL=background_analyse_scan.dev.js.map
