// FishMeNot Login Button
document.getElementsByClassName('fishmenot-sign-in-button')[0].addEventListener('click', function() {
    phishMeNotLogin();
  });
  
// Google Login button
document.getElementsByClassName('g-sign-in-button')[0].addEventListener('click', function() {
  googleLogin();
});

function phishMeNotLogin() {
  fetch('http://localhost:5000/auth/fishmenot/login')
      .then(response => {
          if (response.redirected) {
              window.open(response.url);
          }
      })
      .catch(error => {
          console.error('Error during FishMeNot login:', error);
      });
}

function googleLogin() {
  fetch('http://localhost:5000/auth/google/login')
      .then(response => {
          if (response.redirected) {
              window.open(response.url);
          }
          chrome.runtime.sendMessage({ action: "updatePopup" });
      })
      .catch(error => {
          console.error('Error during Google login:', error);
      });
}