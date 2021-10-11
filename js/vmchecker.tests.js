/*
 * VMware CWS Checker - Main File
 *
 * The VMware CWS Checker is a browser extension is a tool to test security for
 * HTTP & HTTPs based traffic through VMware Cloud Web Security (CWS) offering.
 * It tests CASB, URL filtering, Content Inspection and much more. 
 *
 * Iddo Cohen, August 2021
 *
 * Copyright (C) 2021, Iddo Cohen
 * SPDX-License-Identifier: MIT License
 */

import {config, testingDomains, existingCategories} from './vmchecker.config.js';

var log = console.log.bind(console);
var error = console.error.bind(console);


// Simple Rouding function.
function round(number, precision) {
    const multiplier = Math.pow(10, precision || 0);
    return Math.round(number * multiplier) / multiplier;
}

// Basic Timer Class
function Timer () {
    this._start = performance.now();

    this.elapsed = function() {
        return round((performance.now() - this._start)/1000, 2);
    }

    this.reset = function () {
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


async function doAjax(url, obj={type: undefined, request:undefined}) {
    let ret = [];
    let time;

    let type     = obj.request || "GET";
    let datatype = obj.type    || "html";


    try {
        // Putting everything in separte XHR to get a bit more information
        var xhr = new XMLHttpRequest();
        await $.ajax({
            type: type,
            beforeSend: function() {
                time = new Timer();
            },
            url: url,
            cache: false,
            dataType: datatype,
            xhr: function () {
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

function validateIPaddress(ipaddress) {  
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
    let sase_ip_ranges = await getLocations();

    function text(t, d=dom_process, type="text") {
        if (type == "text"){
            $(d).text(t);
        } else if (type == "html") {
            $(d).html(t);
        }
    }

    async function getLocations () {
        //let data = await doAjax("https://iddocohen.github.io/vmware-sase-check/config/locations.json", "json");
        let data = await doAjax("https://iddocohen.github.io/vmware-sase-check/config/locations.json", {type: "json"});
        if (data[1].status == 200) {
            return data[3].pops;
        }
        return null; 
    }
    async function testSourceIP () {
        if (sase_ip_ranges == null) {
             return [false, `Could not retrieve VMware CWS IPs.`, 7];
        }
        let ret = [];
        let ipify = await doAjax("http://api.ipify.org/");
        if (ipify[1].status == 200) {
            if (validateIPaddress(ipify[1].responseText)) {
                 for (let i = 0; i < sase_ip_ranges.length; ++i) {
                    if (ipInRange(sase_ip_ranges[i].ip, ipify[1].responseText)) {
                        return [true, ipify[1].responseText, sase_ip_ranges[i].pop+"|"+sase_ip_ranges[i].radius];
                    }
                 } 
                 return [false, `You are <strong>partially</strong> behind CWS.`, 1];
            } else {
                return [false, `Not sure if you are behind CWS.`, 2];
            }
        } 
        return [false, `Not sure if you are behind CWS.`, 3]
    }

    text("Testing connection towards VMware CWS . . .");

    let [behindCWS, behindCWStext, behindCWSerror] = await testSourceIP();
    let geoCity = "";
    let geoAccr = 0;

    if (behindCWS) {
        text ("You are behind CWS. Will test further...");
        //geoCity   = await getGeoCity(behindCWStext);
        [geoCity, geoAccr]  = behindCWSerror.split("|");
    } else {
        text ("The response received indicates you are not behind VMware CWS service. Double checking...");
    }

    let [jqXHR, xhr, rtt, data] = await doAjax(cws_url);

    if (xhr.status == 200) {
         if (xhr.responseURL.includes('safe-cws-sase.vmware.com')) { // We double check that we get a response via CWS
            let deferreds = [];
            for (let i = 0; i < testingDomains.length; i++) {
                let newProxyUrl = "https://"+testingDomains[i];
                deferreds.push(doAjax(newProxyUrl));
            }
            //TODO: Better variable names
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

                if (behindCWS) {
                    text (`You are behind VMware CWS. The IP you are using is ${behindCWStext} which resides in ${geoCity} (± ${geoAccr}km).`, dom_process, "html");
                } else {
                    displayMessage(behindCWSerror);
                    text (behindCWStext, dom_process, "html");
                } 
 
            });
        } else {
            displayMessage(8, "danger");
            text(`Request to VMware CWS got changed (${xhr.responseURL})`);
        }
    } else if (xhr.status == 404 && behindCWS == false) {
        displayMessage(4, "danger");
        text ("You are not behind CWS.");
    } else if (xhr.status == 403) {
        displayMessage(5, "danger");
        text("Connection got blocked to CWS.");
    } else {
        displayMessage(6, "danger");
        text(`CWS was not reachable.`);
    }   
}    

async function doTesting(sites) {
    let ret = [];
    for (let i=0; i < sites.length; ++i) {
        let url                     = sites[i].url;
        let expected_code           = sites[i].code;
        let [jqXHR, xhr, rtt, data] = await doAjax(url); 
        let classified              = "";
        let bool                    = false;
        if (expected_code == xhr.status) {
            if (xhr.status == 403) {
                try {
                    if (jqXHR.responseText.includes("VMware Cloud Web Security")) {
                        let forbidden = $.parseHTML(jqXHR.responseText);
                        classified = $(forbidden).find("strong").text();
                        bool = true;
                    }
                } catch (e) {
                    log (e);
                }
            } else {
                bool = true;
            } 
        }
        ret.push([bool, classified, rtt, url, xhr.status]);
    }
    return ret;
}


function lookup(id) {
    for (let i = 0; i < config.length; i++) {
        let o = config[i];
        if (o.id == id) {
            return [o.how, o.fail, o.load, o.websites];            
        }   
    }
    return false;
}

function progressBar(sum, count){
    let num = round((count / sum) * 100);
    $(".progress-bar").css("width", num+"%");
    $(".progress-bar").attr("aria-valuenow", num);
    $(".progress-bar").text(num+"%");
}

function changeButton(object, text, css="primary") {
    $(object).attr("class", "").addClass(`btn btn-outline-${css}`);
    $(object).text(text);
}

function displayMessage(id, type="warning") {
    const url  = `https://iddocohen.github.io/vmware-sase-check`;
    const path = `${url}/errors/${id}.html`;
    const str  = `Warning: Please visit <a class="alert-link" target="_blank" rel="noopener noreferrer" href="${path}">#${id}</a> to get more info.`;
    $('#alert_message').html(str);
    $('.alert').attr('class', '').addClass(`alert alert-${type}`);
    $('.alert').fadeIn();
    $('html, body').animate({ scrollTop: 0 }, 'fast');
}
$(function() {
    $.getJSON("../manifest.json", function (data) { 
        let version = `v${data.version}`;
        let html = $(".navbar-brand").html();
        if (version === "v0.1") {
            version = "beta"
        }
        $(".navbar-brand").html(html+`<small><small><sub>(${version})</sub></small></small>`);   
    });
 
});

$(window).bind("load", function () {
    for (let i = 0; i < existingCategories.length; ++i) {
        const o = existingCategories[i];
        if (!o.isEnabled) { continue };

        const div = `
            <div class="row top30">
                <div class="card">
                    <div class="card-header text-white bg-secondary"><h4>${o.humanReadable}</h4></div>
                </div>
            </div>
            <div class="row row-cols-1 row-cols-md-2 g-4 top15" id="checks_content_${o.id}">
            </div>
        `;
        $(document.body).append(div);
    } 
    for (let i = 0; i < config.length; ++i){
        const o = config[i];
        const div = `
          <div class="col">
            <div class="card">
              <div class="card-header">
                <h5>${o.title}</h5>
                <div class="help-tip"><p>${o.how}</p></div>
              </div>
              <div class="card-body">
                <p class="card-text" id="${o.id}_body_text">${o.detail}<br><br>${o.desc}</p>
                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                    <button class="btn btn-outline-primary" data-tested="no" data-type="test" data-category="${o.category}" type="button" id="${o.id}">Test</button><br>
                </div>
              </div>
              <div class="card-footer">
                  <p class="card-text text-muted right10" id="${o.id}_footer_text"><br></p>
              </div>
            </div>
          </div>
        `;
        $(`#checks_content_${o.category}`).append(div);
    }
    $('.btn-close').on('click', function() {
        $(".alert").attr('class','').addClass('alert');
        $(".alert").fadeOut();
    });
    $('.btn').mouseover(function() {
        let attr = $(this).attr('data-tested');
        if (attr && attr != "no") {
            changeButton(this, "Re-run");
        }
    });
    $('.btn').mouseleave(function() {
        let attr = $(this).attr('data-tested');
        if (attr == 'blocked'){
            changeButton(this, "Blocked", "success");
        } else if (attr == 'unblocked') {
            changeButton(this, "Unblocked", "danger");
        } else if (attr == 'blocked-differently') {
            changeButton(this, "Blocked but...", "warning");
        } else if (attr == 'error') {
            changeButton(this, "Error", "danger");
        }
    });
    $('.btn').on("click", function() {
        let id          = $(this).attr('id');
        let category    = $(this).attr('data-category');
        let button      = $("#"+id);
        let footerText  = $("#"+id+"_footer_text");
        let bodyText    = $("#"+id+"_body_text");

        if (id == "test_all") {
            $('button[data-type="test"]').click();
            return true;
        }
        if (id != "test_all" && id != "cws_check") {
            changeButton(button, "Progress", "secondary");
        }
        switch (category) {
            case "cws": 
                checkCWS("#cws_process","#stats_mean","#stats_std","#stats_quantitle");    
                break;
            case "casb":
            case "urlfilter":
            case "cinspect":
                let [howMessage, failMessage, loadMessage, listWebsites] = lookup(id);
                $(footerText).text(loadMessage);
                let asyncFunc = doTesting(listWebsites);
                if (typeof asyncFunc === "object") {
                    Promise.resolve(asyncFunc).then(function(returnValues) {
                        let [isBlocked, data, rtt, url, code] = returnValues[0];
                        if (returnValues.length > 1) {
                            for (let i=1 ; i < returnValues.length; ++i) {
                                let [isOtherBlocked] = returnValues[i];
                                isBlocked = isBlocked && isOtherBlocked; 
                            }
                        }
                        if (isBlocked == true) {
                            $(button).attr("data-tested","blocked");
                            changeButton(button, "Blocked", "success");
                            $(footerText).html(`Category identified by CWS as <strong>${data}</strong>. Response time was <strong>${rtt}s</strong>`);
                        }else if (isBlocked == false) {
                            // Main website got blocked but other domain parts might have a wrong state, as it got blocked not like the test-case intended to.  
                            //TODO: To be more specific on if other URLs really got blocked by CWS or by other security. 
                            if (returnValues[0][0] && returnValues.length > 1) {
                                $(button).attr("data-tested","blocked-differently");
                                changeButton(button, "Blocked but...", "warning");
                                $(bodyText).html(`Several URLs for given test-case are used for testing. The main URL '${url}' got blocked from CWS but the other URLs returned unexpected return HTTP code, which indicates a wrong configuration. Please double check the configuration.`);
                                $(footerText).html(`Category identified by CWS as <strong>${data}</strong>. Response time was <strong>${rtt}s</strong>`);
                            } else {
                                $(button).attr("data-tested","unblocked");
                                changeButton(button, "Unblocked", "danger");
                                $(bodyText).html(failMessage);
                                $(footerText).html(`Response time was <strong>${rtt}s</strong>`);
                            }
                        } else {
                            $(button).attr("data-tested","error");
                            changeButton(button, "Error", "danger");
                            $(bodyText).html(failMessage);
                            $(footerText).html(`Response time was <strong>${rtt}s</strong>`);
                        }
                        progressBar(config.length, $(".btn-outline-success").length);
                    });
                }
                break;
        }
    });
    $('#cws_check').click();
});

