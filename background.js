function scanURLWithVirusTotal(url, tabId, callback) {
  const API_KEY = 'd952e200fd50390b51eba3157347d8d44f7be039dbafd8091216fdcf428cda3b'; // Replace with your API key
  const API_URL = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${API_KEY}&resource=${url}`;

  fetch(API_URL)
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok.');
      }
      return response.json();
    })
    .then(data => {
      if (data.response_code === 0) {
        throw new Error('URL not found or no information available.');
      }
      const scanAnalytics = {
        score: data.positives || 0,
        totalScans: data.total || 0,
        scanResults: data.scans || {}
        // You can extract and process more data here as needed
      };
      callback(scanAnalytics);
    })
    .catch(error => {
      callback({ error: error.message });
    });
}
