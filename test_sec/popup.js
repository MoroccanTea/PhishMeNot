document.addEventListener('DOMContentLoaded', function () {
    // Récupérer l'onglet actif
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      const currentTab = tabs[0];
  
      // Afficher les informations du site
      document.getElementById('siteInfo').textContent = `URL: ${currentTab.url}`;
  
      // Gérer le clic sur le bouton "Vérifier si le site est suspect"
      document.getElementById('checkPhishing').addEventListener('click', function () {
        checkPhishing(currentTab.url);
      });
  
      // Gérer le clic sur le bouton "Signaler le site"
      document.getElementById('reportSite').addEventListener('click', function () {
        reportSite(currentTab.url);
      });
    });
  });
  
  // Fonction pour vérifier si le site est suspect
  function checkPhishing(url) {
    // Implementez votre logique de vérification ici
    alert(`Vérification si le site est suspect pour : ${url}`);
  }
  
  // Fonction pour signaler un site
  function reportSite(url) {
    // Implementez votre logique de signalement ici
    alert(`Signalement du site : ${url}`);
  }
  