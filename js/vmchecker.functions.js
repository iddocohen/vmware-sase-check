var log = console.log.bind(console);
var error = console.error.bind(console);


// Simple Rouding function.
function round(number, precision) {
    const multiplier = Math.pow(10, precision || 0);
    return Math.round(number * multiplier) / multiplier;
}

// Basic Timer Class
function Timer () {
    //this._start = new Date();
    this._start = performance.now();

    this.elapsed = function() {
        //return (new Date()) - this._start;
        return round((performance.now() - this._start)/1000, 2);
    }

    this.reset = function () {
        //this._start = new Date();
        this._start = performance.now();
    }
}

// Basic Stats Class with sum, mean, std, median, 25% precentitle and 75% precentitle
//TODO: Make it better... create and then delete, really?!
function Stats (oarr) {

    let arr = [...oarr];
    this._asc = arr.sort((a,b) => a-b);

    this._sum = function (c=arr) {
        return c.reduce((a, b) => a + b, 0);
    }

    this._std = function () {
        const diffArr = arr.map(a => (a - this.mean) ** 2);
        return Math.sqrt(this._sum(diffArr) / (arr.length - 1));
    }

    this._quantitle = function (q) {
        const sorted = this._asc;
        const pos = (sorted.length - 1) * q;
        const base = Math.floor(pos);
        const rest = pos - base;
        if (sorted[base + 1] !== undefined) {
            return sorted[base] + rest * (sorted[base + 1] - sorted[base]);
        } else {
            return sorted[base];
        }
    }

    this.sum = round(this._sum(), 2);
    this.mean = round(this.sum / arr.length, 2);
    this.std = round(this._std(), 2);
    this.q75 = round(this._quantitle(.75), 2);
    this.median = round(this._quantitle(.50), 2);
    this.q25 = round(this._quantitle(.25), 2);

    delete this._asc;
    delete this._sum;
    delete this._std;
    delete this._quantitle;
    delete this.sum;

}


async function doAjax(url, type="html") {
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
            dataType: type,
            xhr: function() {
                return xhr;
            },
            success: function(data,status,jqXHR) {
                ret.push(jqXHR);
                ret.push(xhr);
                ret.push(time.elapsed());
                ret.push(data)
            },
            error: function(jqXHR) {
                ret.push(jqXHR);
                ret.push(xhr);
                ret.push(time.elapsed());
                ret.push(undefined);
            },
            timeout: 5000
        });
    } catch (e) {
       //error(e)
    }
    return ret;
}
function ValidateIPaddress(ipaddress) {  
    if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {  
        return true  
    }  
    return false  
}  

function ipInRange(cidr,ip) {
   function ipToNum (str) {
        let octets = str.split(".").map(Number);
        return (+octets[0]<<24) + (+octets[1]<<16) + (+octets[2]<<8) + (+octets[3]); 
   }
   function ipMask (size) {
        return -1<<(32-size);
   }

   let [network, mask] = cidr.split("/");

   let nnetwork  = ipToNum(network);
   let nmask     = ipMask(mask);
   let nip       = ipToNum(ip);
  
   if ((nip & nmask) == nnetwork) {
        return true;
   }

   return false;
}

async function checkCWS(dom=".text") {
    let cws_url = "https://safe-cws-sase.vmware.com/";
    let top10_domains = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "stackoverflow.com",
        "wikipedia.org",
        "outlook.live.com",
        "github.com",
        "amazon.com"
    ];

    let sase_ip_ranges = [
        "216.221.24.0/21",
        "64.186.24.0/21",
        "136.144.96.0/19",
        "207.66.112.0/21"
    ];

    function text(t, d=dom) {
        $(dom).text(t);
    }

    async function testSourceIP () {
        let ipify = await doAjax("http://api.ipify.org/");
        if (ipify[1].status == 200) {
            if (ValidateIPaddress(ipify[1].responseText)) {
                 for (let i = 0; i < sase_ip_ranges.length; i++) {
                    if (ipInRange(sase_ip_ranges[i], ipify[1].responseText)) {
                        log(ipify[1].responseText);
                        return true;
                    }
                 }
            }
        }
        return false;
    }

    text("Testing connection towards VMware Cloud Web Security (CWS) . . .");

    let behindCWS = await testSourceIP();

    if (behindCWS) {
        text ("You are behind CWS. Will test further...");
    }

    let [jqXHR, xhr, rtt, data] = await doAjax(cws_url);

    if (xhr.status == 200) {
        if (xhr.responseURL.includes('www.vmware.com')) { // If we get vmware.com then we got redirected, as we are not behind CWS.
            if (!behindCWS) {
                text("The response received indicates you are not behind VMware CWS service");
            }else {
                text("You are behind CWS but you got redirect back to VMware.com. Something is very wrong."); 
            }
        } else if (xhr.responseURL.includes('safe-cws-sase.vmware.com')) { // We double check that we get a response via CWS
            let deferreds = [];
            for (let i = 0; i < top10_domains.length; i++) {
                let new_proxy_url = "https://"+top10_domains[i];
                deferreds.push(doAjax(new_proxy_url));
            }
            /* TODO: Explore if I should do this this way. I do not think iti will bring a benefit
            var deferred = $.Deferred();
            $.when.apply($, deferreds)
		        .done(function () { deferred.resolve(deferreds); })
		        .fail(function () { deferred.reject(deferreds); });

            deferred.promise().done(function(x) {
                for (let i = 0; i < x.length; i++) {
                    log(x[i].then());
                }
            });
            */
            $.when.apply($, deferreds).done(function(){
                let rtt_arr = [];
                for (let i = 0; i < arguments.length; i++){
                    let [res_jqXHR, res_xhr, res_rtt] = arguments[i];
                    if (res_xhr.status == 200 || res_xhr.status == 403) {
                        let res_url = new URL(res_xhr.responseURL);
                        rtt_arr.push(res_rtt);
                    }
                }
                let stats = new Stats(rtt_arr);
                let str = "";
                for (const [k, v] of Object.entries(stats)) {
                        str += k+" = "+v+"s ";
                }
                text(`Performance of reaching Top 10 Websites behind CWS: ${str}`);
            });
        } else {
            text("CWS request was changed to '"+xhr.responseURL+"'. This will cause CWS not to work in your environment.");
        }
    } else if (xhr.status == 403) {
        text("Connection got blocked to CWS. Please check browser PAC/Socket/Proxy settings or firewall settings.");
    } else {
        text("CWS is not reachable. Please try again later.");
    }   
}    


$(function () {
    $('.btn').click(function() {
        checkCWS();    
    });
});

