

chrome.runtime.onInstalled.addListener(function() {
    //initiateAuthFlow(); - No need to force login on install
});

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "login") {
        handleLogin();
    }
});


// LOGIN using Google
function handleLogin() {
    const clientId = '1012335321307-toffck12nta79m0ncgslrah50tm6rc5d.apps.googleusercontent.com'; //TODO: Retrieve from .env 
    const scopes = 'email profile'; // Other scopes will be added as needed an depending on the user settings
    const redirectUri = chrome.identity.getRedirectURL(); // This will be used by Google for redirecting after authentication
    const authUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${clientId}&response_type=id_token&access_type=offline&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scopes)}`;

    chrome.identity.launchWebAuthFlow({
        url: authUrl,
        interactive: true
    }, function(redirectUrl) {
        if (chrome.runtime.lastError || !redirectUrl) {
            console.error(chrome.runtime.lastError ? chrome.runtime.lastError.message : 'No redirect URL');
            return;
        }
    
        // Extract the ID token from the redirect URL
        const params = new URL(redirectUrl).hash.split('&').map(p => p.split('='));
        const idTokenParam = params.find(p => p[0] === '#id_token' || p[0] === 'id_token');
        if (idTokenParam && idTokenParam.length > 1) {
            const idToken = idTokenParam[1];
            const user = parseJwt(idToken);
            // This function is used to save the user information
            chrome.storage.sync.set({ idToken: idToken }, function() {
                console.log("idToken saved.");
            });
            chrome.storage.sync.set({ user: user }, function() {
                console.log("User information retrieved & saved.");
            });
        } else {
            console.error('No ID token found in redirect URL');
        }
    });
};


// This function is used to retrieve the user information from the storage
chrome.storage.sync.get('user', function(data) {
    if (data.user) {
        //TODO: Use the user information to display it in the popup
    } else {
        console.log("No user information found, not logged in using Google");
    }
});

// This function is used to decode the JWT token and extract the user information
function parseJwt (idtoken) {
    try {
        const base64Url = idtoken.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    } catch (e) {
        console.error("Error decoding JWT", e);
        return null;
    }
};