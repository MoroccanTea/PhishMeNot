// Variable pour indiquer si l'extension est activée
let extensionActive = true;

// Fonction pour afficher la popup lorsqu'un utilisateur visite un site
function afficherPopupSite() {
  // Vérifier si l'extension est active
  if (!extensionActive) {
    return;
  }

  // Récupérer l'adresse IP du site
  obtenirAdresseIP().then((adresseIP) => {
    // Récupérer le fournisseur d'hébergement
    obtenirHebergement().then((hebergement) => {
      // Calculer un taux de risque (remplacez par votre propre logique)
      const tauxRisk = Math.floor(Math.random() * 101); // Exemple : un taux de risque aléatoire

      // Construire le message détaillé
      const messageDetails = `Adresse IP : ${adresseIP}\nHébergement : ${hebergement}\nTaux de risque : ${tauxRisk}%`;

      // Afficher la popup avec les détails
      alert(messageDetails);
    });
  });
}

// Fonction pour activer/désactiver l'extension
function toggleExtension() {
  extensionActive = !extensionActive;
  alert(`Extension ${extensionActive ? 'activée' : 'désactivée'}`);
}

// Fonction pour créer l'icône de l'extension dans la barre d'outils
function creerIconeExtension() {
  const iconPath = {
    "16": "icon-16.png",
    "32": "icon-32.png",
    "198": "icon-198.png",
  };

  chrome.action.setIcon({ path: iconPath });
  chrome.action.onClicked.addListener(toggleExtension);
}

// Fonction pour effectuer une analyse du nom de domaine et retourner un message informatif
function analyserNomDomaine() {
  // ... (Code existant)
  return { message, utiliseHTTPS };
}

// Fonction pour afficher une popup stylisée en fonction de la sécurité du site
function afficherPopupSecurite() {
  // ... (Code existant)

  // Ajouter un gestionnaire d'événements pour la visite d'un site
  chrome.webNavigation.onCompleted.addListener((details) => {
    if (extensionActive) {
      afficherPopupSite();
    }
  });
}

// Appeler la fonction lors du chargement de l'extension
creerIconeExtension();
afficherPopupSecurite();
