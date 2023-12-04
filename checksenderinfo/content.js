chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    if (request.action === "checkPhishing") {
      const emailSubject = document.querySelector('h2.hP');
      const senderName = document.querySelector('span.gD');
  
      let message = "This email seems legitimate.";
  
      if (emailSubject && senderName) {
        const subject = emailSubject.innerText.trim();
        const name = senderName.innerText.trim();
  
        // Call your phishing detection function (checkPhishing) here with subject and name
        if (checkPhishing(subject, name)) {
          message = "This email may be a phishing attempt.";
        }
      } else {
        message = "Unable to retrieve email information.";
      }
  
      sendResponse({ message: message });
    }
  });
  
  function checkPhishing(emailSubject, senderName) {
    // Your existing phishing detection logic here
    // Modify or replace this function as needed
    // For example, use the logic you provided earlier
    const phishingSubjectPatterns = [
      /\b(?:urgent|verify|account|password|confirm|login)\b/i,
      /\b(?:security|fraud|alert|update|suspend)\b/i,
      /\b(?:paypal|bank|login|irs|email)\b/i
    ];
  
    const phishingSenderPatterns = [
      /\b(?:official|admin|support)\b/i,
      /\b(?:paypal|bank|irs|security)\b/i
    ];
  
    for (const subjectPattern of phishingSubjectPatterns) {
      if (subjectPattern.test(emailSubject)) {
        return true;
      }
    }
  
    for (const senderPattern of phishingSenderPatterns) {
      if (senderPattern.test(senderName)) {
        return true;
      }
    }
  
    return false;
  }
  