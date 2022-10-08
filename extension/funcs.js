document.getElementById('clickk').addEventListener('click',getCurrentTabUrl)

function getCurrentTabUrl () {

    chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
        let url = tabs[0].url;
        if(url.includes('https')){
            // alert("site is safe")
        }
        else{
            alert("site is not safe")
            url.href = "www.google.com"
        }
        window.location.replace(window.location.href);
        var req = new XMLHttpRequest();
            req.open('GET', url, false);
            req.send(null);
            var headers = req.getAllResponseHeaders().toLowerCase();
            // alert(headers);
});    
  }

chrome.extension.onRequest.addListener(function(request, sender) {
});
