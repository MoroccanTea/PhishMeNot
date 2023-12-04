chrome.runtime.onInstalled.addListener(() => {
    checkAuthAndUpdatePopup();
});

chrome.runtime.onStartup.addListener(() => {
    checkAuthAndUpdatePopup();
});

function checkAuthAndUpdatePopup() {
    fetch('http://localhost:5000/auth/status')
        .then(response => response.json())
        .then(data => {
            if (data.authenticated) {
                chrome.action.setPopup({ popup: 'views/dashboard/dashboard.html' }); // For authenticated users
            } else {
                chrome.action.setPopup({ popup: 'views/auth/auth.html' }); // For unauthenticated users
            }
        })
        .catch(error => console.error('Error:', error));
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "updatePopup") {
        checkAuthAndUpdatePopup();
    }
});

chrome.webNavigation.onCommitted.addListener((details) => {
    // DON'T check for phishing on the 127.0.0.1 or localhost
    if (details.url.includes('127.0.0.1') || details.url.includes('localhost')) {
        return;
    }
    else {
        checkUrl(details.url);
    }
});

function checkUrl(url) {
    fetch('http://localhost:5000/analyze/url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url, hostname: new URL(url).hostname }),
        credentials: 'include'
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'unsage') {
                console.log('Phishing detected!');
            }
        })
        .catch(error => console.error('Error:', error));
}
