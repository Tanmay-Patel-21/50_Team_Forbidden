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
            // # X-Frame-Options Referrer-Policy Content-Security-Policy Permissions-Policy X-Content-Type-Options Strict-Transport-Security X-XSS-Protection
            let missingHeaders = []
            let presentHeaders = []

            if(headers.includes('X-Frame-Options')){
                presentHeaders.push("X-Frame-Options")
                console.log("X-Frame-Options");
            }
            else{
                missingHeaders.push("x-frame-options")
            }

            if(headers.includes('referrer-policy')){
                presentHeaders.push("referrer-policy")
            }
            else{
                missingHeaders.push("referrer-policy")
            }

            if(headers.includes('x-content-security-policy')){
                presentHeaders.push("x-content-security-policy")
            }
            else{
                missingHeaders.push("x-content-security-policy")
            }

            if(headers.includes('x-content-type-options')){
                presentHeaders.push("x-content-type-options")
            }
            else{
                missingHeaders.push("x-content-type-options")
            }

            if(headers.includes('strict-transport-security')){
                presentHeaders.push("strict-transport-security")
            }
            else{
                missingHeaders.push("strict-transport-security")
            }

            if(headers.includes('X-XSS-Protection')){
                presentHeaders.push("X-XSS-Protection")
            }
            else{
                missingHeaders.push("X-XSS-Protection")
            }
            document.write("Missing Headers: "+missingHeaders);
            // alert("<br>Missing Headers:" + headers.includes("x-content-security-policy"))
            // alert(headers);
});    
}
