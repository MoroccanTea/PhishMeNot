// Fonction pour effectuer une analyse du nom de domaine et retourner un message informatif
function analyserNomDomaine() {
  const url = new URL(window.location.href);
  const domaine = url.hostname;

  // Vérifier si le site utilise HTTPS
  const utiliseHTTPS = url.protocol === "https:";

  // Exemple : Vérifier s'il y a des caractères spéciaux dans le domaine
  const caracteresSpeciaux = /[!@#$%^&*(),.?":{}|<>]/;
  const aCaracteresSpeciaux = caracteresSpeciaux.test(domaine);

  // Exemple : Construire le message en fonction des vérifications
  let message = utiliseHTTPS ? "Ce site est sécurisé !" : "Attention ! Ce site peut être suspect. Veuillez être prudent.";
  if (aCaracteresSpeciaux) {
    message = "Attention ! Ce site peut être suspect. Veuillez être prudent.";
  }

  return { message, utiliseHTTPS };
}

// Fonction pour afficher une popup stylisée en fonction de la sécurité du site
function afficherPopupSecurite() {
  // Créer un élément div pour la popup
  var popupDiv = document.createElement("div");
  popupDiv.id = "popup-securite";

  // Effectuer une analyse du nom de domaine et obtenir des informations détaillées
  const detailsAnalyseNomDomaine = analyserNomDomaine();

  // Construire le message de la popup
  popupDiv.innerHTML = `<strong>${detailsAnalyseNomDomaine.message}</strong> <a href="#" id="details-lien">Plus de détails</a>`;

  // Ajouter l'élément div au corps de la page
  document.body.appendChild(popupDiv);

  // Ajouter l'animation de cadre (LED)
  popupDiv.style.animation = "borderAnimation 1s infinite";

  // Positionner la popup à droite
  popupDiv.style.position = "fixed";
  popupDiv.style.top = "50%";
  popupDiv.style.right = "20px";  // Ajustez la distance depuis le bord droit selon vos préférences
  popupDiv.style.transform = "translateY(-50%)";

  // Supprimer la popup après 10 secondes
  setTimeout(function () {
    var popup = document.getElementById("popup-securite");
    if (popup) {
      popup.remove();
    }
  }, 10000);  // 10000 millisecondes (10 secondes)

  // Ajouter un gestionnaire d'événements pour le lien "Plus de détails"
  const detailsLien = document.getElementById("details-lien");
  if (detailsLien) {
    detailsLien.addEventListener("click", afficherDetails);
  }
}

// Appeler la fonction lors du chargement de la page
afficherPopupSecurite();

// Fonction pour afficher des détails supplémentaires lorsqu'on clique sur "Plus de détails"
async function afficherDetails(event) {
  event.preventDefault();

  // Récupérer l'adresse IP du site
  const adresseIP = await obtenirAdresseIP();

  // Récupérer le fournisseur d'hébergement
  const hebergement = await obtenirHebergement();

  // Calculer un taux de risque (remplacez par votre propre logique)
  const tauxRisk = 50;

  // Construire le message détaillé
  const messageDetails = `Adresse IP : ${adresseIP}<br>Hébergement : ${hebergement}<br>Taux de risque : ${tauxRisk}%`;

  // Afficher les détails dans une boîte de dialogue
  alert(messageDetails);
}

// Fonction pour obtenir l'adresse IP à partir de ipinfo.io
async function obtenirAdresseIP() {
  try {
    const reponse = await fetch('https://ipinfo.io/json');
    const donnees = await reponse.json();
    return donnees.ip;
  } catch (erreur) {
    console.error('Erreur lors de la récupération de l\'adresse IP :', erreur);
    return 'Non disponible';
  }
}

// Fonction pour obtenir le fournisseur d'hébergement à partir de Whois
async function obtenirHebergement() {
  try {
    const reponse = await fetch(`https://www.whois.com/whois/${window.location.hostname}`);
    const texteHTML = await reponse.text();
    const matchHebergement = texteHTML.match(/Registrar:\s*(.+?)\s/);
    return matchHebergement ? matchHebergement[1] : 'Non disponible';
  } catch (erreur) {
    console.error('Erreur lors de la récupération du fournisseur d\'hébergement :', erreur);
    return 'Non disponible';
  }
}
