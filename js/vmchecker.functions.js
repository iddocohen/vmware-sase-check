var log = console.log.bind(console);
var error = console.error.bind(console);


// Basic Timer Class
function Timer () {
    this._start = new Date();

    this.elapsed = function() {
        return (new Date()) - this._start;
    }

    this.reset = function () {
        this._start = new Date();
    }
}


async function doAjax(url) {
    let ret = [];
    let time;
    try {
        // Putting everything in separte XHR to get a bit more information
        var xhr = new XMLHttpRequest();
        await $.ajax({
            type: "GET",
            beforeSend: function() {
                time = new Timer();
            },
            url: url,
            cache: false,
            dataType: "html",
            xhr: function() {
                return xhr;
            },
            success: function(data,status,jqXHR) {
                ret.push(jqXHR);
                ret.push(xhr);
            },
            error: function(jqXHR) {
                ret.push(jqXHR);
                ret.push(xhr);
            },
            timeout: 3000
        });
    } catch (e) {
       //error(e)
    }
    ret.push(time.elapsed());
    return ret;
}

async function checkCWS(dom=".text") {
    function text(t) {
        $(dom).text(t);
    }
    text("Testing connection towards VMware Cloud Web Security (CWS) . . .");

    let cws_url = "https://safe-cws-sase.vmware.com/";
    let proxy_url = "https://safe-cws-sase.vmware.com/safeview-auth-server/proxy_auth?url=%BASE64%&pnr=2"
    let top10_domains = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "stackoverflow.com",
        "wikipedia.org",
        "live.com",
        "yahoo.com",
        "amazon.com"
    ];
    let [jqXHR, xhr, rtt] = await doAjax(cws_url);

    if (xhr.status != 200 && xhr.status != 403) {
        text(xhr);
        return 0;
    }

    if (xhr.status == 200) {
        if (xhr.responseURL.includes('www.vmware.com')) { // If we get vmware.com then we got redirected, as we are not behind CWS.
            text("The response received indicates you are not behind VMware CWS service");
        } else if (xhr.responseURL.includes('safe-cws-sase.vmware.com')) { // We double check that we get a response via CWS
            let deferreds = [];
            for (let i = 0; i < top10_domains.length; i++) {
                let base64str = btoa("https://"+top10_domains[i]);
                let new_proxy_url = proxy_url.replace(/%BASE64%/g, base64str);
                deferreds.push(doAjax(new_proxy_url));
            }
            $.when.apply($, deferreds).done(function(){
                for (let i = 0; i < arguments.length; i++){
                    let [res_jqXHR, res_xhr, res_rtt] = arguments[i];
                    if (res_xhr.status == 200 || res_xhr.status == 403) {
                        let res_url = new URL(res_xhr.responseURL);
                        let cws_only_rtt = res_rtt - rtt;
                        log(res_url.origin+" " + res_rtt + " "+ rtt + " " +cws_only_rtt);
                    }
                } 
            });
        } else {
            text("CWS request was changed to '"+xhr.responseURL+"'. This will cause CWS not to work in your environment");
        }
    } else {
        text("CWS is not reachable. Please try again later.");
    }   
}    


$(function () {
    $('.btn').click(function() {
        checkCWS();    
    });
});

