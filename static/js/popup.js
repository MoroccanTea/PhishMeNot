// FishMeNot Login Button
document.getElementsByClassName('fishmenot-sign-in-button')[0].addEventListener('click', function() {
    chrome.runtime.sendMessage({action: "phishmenotLogin"});
  });
  
  // Google Login button
  document.getElementsByClassName('g-sign-in-button')[0].addEventListener('click', function() {
    chrome.runtime.sendMessage({action: "googleLogin"});
  });