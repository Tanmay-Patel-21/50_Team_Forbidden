document.getElementById('clickk').addEventListener('click',getCurrentTabUrl)

function getCurrentTabUrl () {
    chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
        let url = tabs[0].url;
        if(url.includes('https')){
            alert("site is safe")
        }
        else{
            alert("site is not safe")
        }
    });
    
  }
