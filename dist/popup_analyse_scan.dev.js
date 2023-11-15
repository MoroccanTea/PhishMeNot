"use strict";

function _readOnlyError(name) { throw new Error("\"" + name + "\" is read-only"); }

document.addEventListener('DOMContentLoaded', function () {
  var autoScanToggle = document.getElementById('autoScanToggle');
  autoScanToggle.addEventListener('change', function () {
    // Variable pour stocker l'état du scan automatique (par défaut, il est activé)
    var isAutoScanEnabled = autoScanToggle.checked;

    if (isAutoScanEnabled) {
      // Logique pour activer le scan automatique
      var _enableAutoScan = function _enableAutoScan() {
        isAutoScanEnabled = (_readOnlyError("isAutoScanEnabled"), true);
        console.log('Scan automatique activé');
      };

      console.log('Scan automatique activé');
    } else {
      // Logique pour désactiver le scan automatique
      var _disableAutoScan = function _disableAutoScan() {
        isAutoScanEnabled = (_readOnlyError("isAutoScanEnabled"), false);
        console.log('Scan automatique désactivé');
      };

      console.log('Scan automatique désactivé');
    }
  });
}); // Écouteur d'événement pour détecter les messages depuis le popup

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.action === 'toggleAutoScan') {
    var isEnabled = request.isEnabled;

    if (isEnabled && !isAutoScanEnabled) {
      enableAutoScan();
    } else if (!isEnabled && isAutoScanEnabled) {
      disableAutoScan();
    }
  }
});
//# sourceMappingURL=popup_analyse_scan.dev.js.map
