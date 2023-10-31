//Detect phishing site
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    const url = new URL(details.url);

    fetch('http://localhost:5000/analyze', {
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
  },
  { urls: ["<all_urls>"] },
  []
);
  