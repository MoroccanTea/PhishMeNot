//Detect phishing site
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    const url = new URL(details.url);
  
    const fetchPromise = fetch('http://localhost:5000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: url.href,
        hostname: url.hostname,
      })
    })
    .then(response => response.json())
    .then(data => {
      if (data.status === "unsafe") {
        alert("Potential phishing site detected.");
      }
    });

    // API might be off or dead, Disable extension if it takes too long
    const timeoutPromise = new Promise((resolve, reject) => {
      setTimeout(() => {
        resolve('timeout');
      }, 5000);
    });
    
    
    Promise.race([fetchPromise, timeoutPromise])
    .then(result => {
      if (result === 'timeout') {
        console.error('Request timed out. Disabling extension.');
        chrome.runtime.reload();
      }
    })
    .catch(error => {
      console.error(`An error occurred: ${error}`);
    });

  },
  { urls: ["<all_urls>"] }
);
