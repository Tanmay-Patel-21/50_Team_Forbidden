document.getElementById('clickk').addEventListener('click',getCurrentTabUrl)

function getCurrentTabUrl () {

    chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
        let url = tabs[0].url;
        if(url.includes('https')){
            alert("site is safe")
            
        }
        else{
            alert("site is not safe")
            url.href = "www.google.com"
        }
        var req = new XMLHttpRequest();
            req.open('GET', url, false);
            req.send(null);
            var headers = req.getAllResponseHeaders().toLowerCase();
            alert(headers);
    });

    chrome.webRequest.onBeforeRequest.addListener(
        function(details) { return {cancel: true}; },
        {urls: ["*://www.evil.com/*"]},
        ["blocking"]
      );
    
  }

