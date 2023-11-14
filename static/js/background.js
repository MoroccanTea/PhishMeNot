chrome.runtime.onInstalled.addListener(function() {
    initiateAuthFlow();
});

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "login") {
        initiateAuthFlow(sendResponse);
        return true;  
    }
});

function initiateAuthFlow(sendResponse) {
    chrome.identity.launchWebAuthFlow(
        {
            url: 'http://localhost:5000/login',
            interactive: true,
        },
        function(redirectUrl) {
            if (chrome.runtime.lastError || !redirectUrl) {
                console.error('Authentication failed', chrome.runtime.lastError);
                sendResponse && sendResponse({status: 'failure', error: chrome.runtime.lastError});
                return;
            }

            // Extract token from the redirect URL
            const urlParams = new URLSearchParams(new URL(redirectUrl).search);
            const token = urlParams.get('token'); // Assuming the token parameter name is 'token'

            if (token) {
                console.log('Google login successful. Token:', token);
                // Store the token on chrome.storage
                chrome.storage.sync.set({ 'authToken': token }, function() {
                    console.log('Token saved.');
                });

                // Notify popup or content script about successful login
                sendResponse && sendResponse({status: 'success'});
            } else {
                console.error('No token found in redirect URL');
                sendResponse && sendResponse({status: 'failure', error: 'No token found'});
            }
        }
    );
}
