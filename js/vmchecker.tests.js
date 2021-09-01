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

    this.sum    = round(this._sum(), 2);
    this.mean   = round(this.sum / arr.length, 2);
    this.std    = round(this._std(), 2);
    this.q75    = round(this._quantitle(.75), 2);
    this.median = round(this._quantitle(.50), 2);
    this.q25    = round(this._quantitle(.25), 2);

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

async function checkCWS(dom_process, dom_mean, dom_std, dom_quantitle) {
    let cws_url = "https://safe-cws-sase.vmware.com/safeview-static/img/input-icons.png";
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
        "159.100.166.0/24",
        "207.66.112.0/21"
    ];

    function text(t, d=dom_process) {
        $(d).text(t);
    }

    async function testSourceIP () {
        let ipify = await doAjax("http://api.ipify.org/");
        if (ipify[1].status == 200) {
            if (ValidateIPaddress(ipify[1].responseText)) {
                 for (let i = 0; i < sase_ip_ranges.length; i++) {
                    if (ipInRange(sase_ip_ranges[i], ipify[1].responseText)) {
                        return ipify[1].responseText;
                    }
                 }
            }
        }
        return "";
    }

    async function getGeoCity (ip) {
        let ipapi = await doAjax("http://ip-api.com/json/"+ip, "json");
        if (ipapi[1].status == 200){
            if (ipapi[3].hasOwnProperty("city")) {
                return ipapi[3].city;            
            }
        }
        return "";
    }

    text("Testing connection towards VMware CWS . . .");

    let behindCWS = await testSourceIP();
    let geoCity = "";

    if (behindCWS != "") {
        text ("You are behind CWS. Will test further...");
        geoCity   = await getGeoCity(behindCWS);
    } else {
        text ("The response received indicates you are not behind VMware CWS service");
        return 0;
    }

    let [jqXHR, xhr, rtt, data] = await doAjax(cws_url);

    if (xhr.status == 200) {
         if (xhr.responseURL.includes('safe-cws-sase.vmware.com')) { // We double check that we get a response via CWS
            let deferreds = [];
            for (let i = 0; i < top10_domains.length; i++) {
                let new_proxy_url = "https://"+top10_domains[i];
                deferreds.push(doAjax(new_proxy_url));
            }
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
                text(`${stats.mean}s`, dom_mean);
                text(`${stats.std}s`, dom_std);
                text(`${stats.q75}s | ${stats.median}s | ${stats.q25}s`, dom_quantitle);
                let str = `You are behind VMware CWS. The IP you are using is ${behindCWS}`;
                if (geoCity != "") {
                    str += ` in ${geoCity}`;
                } 
                text(str);
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

async function block_website(site) {
    let [jqXHR, xhr, rtt, data] = await doAjax(site); 
    let ret = [];
    let classified = "";
    if (xhr.status == 403) {
        try {
            if (jqXHR.responseText.includes("VMware Cloud Web Security")) {
                let forbidden = $.parseHTML(jqXHR.responseText);
                classified = $(forbidden).find("strong").text();
            }
        } catch (e) {
            log (e);
        } 
        ret.push(classified);
        ret.push(true);
    } else if (xhr.status == 200) {
        ret.push(classified);
        ret.push(false);
    } else {
        ret.push(classified);
        ret.push(undefined);
    }
    ret.push(rtt);
    return ret;
}

config = [
     { 
       title: "Block proxy avoidance and anonymizers websites",
       desc : "This test tries to connect to an proxy websites. Failing this test means you have not configured block 'Proxy Avoidance and Anonymous' under 'Web Category'.",
       id: "block_proxy",
       category: "website",
       website: "https://www.proxysite.com/assets/images/logo.png"
     },
     { 
       title: "Block gambling content",
       desc : "This test tries to connect to gambling website. Failing this test means you have not configured block 'Gambling' under 'Web Category'.",
       id: "block_gambling",
       category: "website",
       website: "https://www.bet365.com/sports-assets/sports/FooterModule/assets/bet365-logo.svg"
     },
     { 
       title: "Block access to adult and pornography content",
       desc: "This test attempts to visit a known adult website and download a icon. Failing this test means you have not configured block 'Adult and Pornography' under 'Web Category'.",
       id: "block_adult",
       category: "website",
       website: "https://static-hw.xvideos.com/v3/img/skins/default/favicon.ico"
     },
     {
        title: "Block access to known phishing content",
        desc: "This test attempts to download icon from a known phishing website.",
        id: "block_phising",
        category: "website",
        website: "https://mtron.in/images/favicon.ico"
     },
     {
        title: "Block malware over HTTPs",
        desc: "This test attempts to download malware over HTTPs",
        id: "block_https_malware",
        category: "website",
        website: "https://secure.eicar.org/eicar.com.txt"
     },
     {
        title: "Block malware over HTTP",
        desc: "This test attempts to download malware over HTTP",
        id: "block_http_malware",
        category: "website",
        website: "http://www.rexswain.com/eicar2.zip"
     },
     {
        title: "Block malware download from cloud app",
        desc: "This test attempts to download a malware from popular cloud applications",
        id: "block_cloud_malware",
        category: "website",
        website: "https://security-scorecard.s3.us-east-2.amazonaws.com/eicar_com.zip"
     },
     {
        title: "Block file-based exploit",
        desc: "Checks whether you are protected from known file-based exploits.",
        id: "block_file_exploits",
        category: "website",
        website: "https://storage.googleapis.com/dummyfile-storage-securityscorecard/PoC-test-pdf.pdf"
     },

];

function lookup(id) {
    for (let i = 0; i < config.length; i++) {
        let o = config[i];
        if (o.id == id) {
            return o.website;            
        }   
    }
    return false;
}

function progress(sum, count){
    let num = round((count / sum) * 100);
    $(".progress-bar").css("width", num+"%");
    $(".progress-bar").attr("aria-valuenow", num);
    $(".progress-bar").text(num+"%");
}

$(window).bind("load", function () {
    for (let i = 0; i < config.length; i++){
        let o = config[i];
        let div = `
          <div class="col">
            <div class="card">
              <div class="card-header">
                <div class="help-tip"></div>
                <h5>${o.title}</h5>
              </div>
              <div class="card-body">
                <p class="card-text">${o.desc}</p>
                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                    <button class="btn btn-outline-primary" data-tested="no" data-type="test" data-category="${o.category}" type="button" id="${o.id}">Test</button><br>
                </div>
              </div>
              <div class="card-footer">
                  <p class="card-text text-muted right10"><br></p>
              </div>
            </div>
          </div>
        `;
        $("#checks_content").append(div);
    }
    $('.btn').mouseover(function() {
        let attr = $(this).attr('data-tested');
        if (attr == 'blocked'){
            $(this).removeClass("btn-outline-success");
            $(this).addClass("btn-outline-primary");
            $(this).text("Re-run Test");
        } else if (attr == 'unblocked' || attr == 'error') {
            $(this).removeClass("btn-outline-danger");
            $(this).addClass("btn-outline-primary");
            $(this).text("Re-run Test");
        }
    })
    $('.btn').mouseleave(function() {
        let attr = $(this).attr('data-tested');
        if (attr == 'blocked'){
            $(this).addClass("btn-outline-success");
            $(this).removeClass("btn-outline-primary");
            $(this).text("Blocked");
        } else if (attr == 'unblocked' || attr == 'error') {
            $(this).addClass("btn-outline-danger");
            $(this).removeClass("btn-outline-primary");
            if ( attr == 'unblocked') {
                $(this).text("Unblocked");
            }else {
                $(this).text("Error");
            }
        }
    });
    $('.btn').on("click", function() {
        let id = $(this).attr('id');
        let category = $(this).attr('data-category');

        if (id == "test_all") {
            $('button[data-type="test"]').click();
            return true;
        }
         
        switch (category) {
            case "cws": 
                checkCWS("#cws_process","#stats_mean","#stats_std","#stats_quantitle");    
                break;
            case "website":
                let website = lookup(id);
                let func = block_website(website);
                if (typeof func === "object") {
                    Promise.resolve(func).then(function(value) {
                        let [data, bool, rtt] = value;
                        button = $("#"+id);
                        if (bool == true) {
                            $(button).removeClass("btn-outline-primary");
                            $(button).removeClass("btn-outline-danger");
                            $(button).addClass("btn-outline-success");
                            $(button).attr("data-tested","blocked");
                            $(button).text('Blocked');
                            $(button).parent().parent().parent().find("p.text-muted").text("Category identified by CWS as '"+data+"'. Response time was "+rtt+"s");
                        }else{
                            $(button).removeClass("btn-outline-primary");
                            $(button).removeClass("btn-outline-success");
                            $(button).addClass("btn-outline-danger");
                            $(button).parent().parent().parent().find("p.text-muted").text("Response time was "+rtt+"s");
                        }
                        if (bool == false) {
                            $(button).attr("data-tested","unblocked");
                            $(button).text('Unblocked');
                        }else if (bool == undefined){
                            $(button).attr("data-tested","error");
                            $(button).text('Error');
                        }
                        progress(config.length, $(".btn-outline-success").length);
                    });
                }
                break;
        }
    });
    $('#cws_check').click();
});

