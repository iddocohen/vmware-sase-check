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

import {ext, faqConfig, defaultTestConfig, defaultTestingDomains, existingCategories} from './vmchecker.config.js';

var log = console.log.bind(console);
var error = console.error.bind(console);

var testingDomains = [];
var testConfig = [];

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

// Basic Stats Class with sum, mean, std, median, 25% percentile and 75% percentile
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

async function doAjax(url, obj={type: undefined, request:undefined, payload:undefined}) {
    // Here a very good article explaining why I cannot use performance.time in XHR domain. https://www.dynatrace.com/support/help/how-to-use-dynatrace/real-user-monitoring/basic-concepts/user-actions
    // This one is good as well https://web.dev/ttfb/
    // Question however is how does Google Chrome do it anyway?
    let ret = [];
    let time;

    let type     = obj.request || "GET";
    let datatype = obj.type    || "html";
    let payload  = obj.payload || "";

    var xhr = new XMLHttpRequest();
    let ajaxBase = {
            type: type,
            beforeSend: function() {
                time = new Timer();
            },
            url: url,
            cache: false,
            xhr: function () {
                return xhr;
            },
            success: function(data,status,jqXHR) {
                ret.push(jqXHR);
                ret.push(xhr);
                ret.push(time.elapsed());
                ret.push(data)
            },
            error: function(jqXHR, exception) {
                let msg = '';
                if (jqXHR.status === 0) {
                    msg = 'No connection. Verify network.';
                } else if (exception === 'parsererror') {
                    msg = 'Requested JSON parse failed.';
                } else if (exception === 'timeout') {
                    msg = 'Time out error.';
                } else if (exception === 'abort') {
                    msg = 'Ajax request aborted.';
                } 
                ret.push(jqXHR);
                ret.push(xhr);
                ret.push(time.elapsed());
                ret.push(msg);
            }
    }

    let ajaxFinal = {};

    if (type === "GET"){
        ajaxFinal = {
            ...ajaxBase, 
            dataType: datatype,
            /* TODO: Investigate maybe if the below is better for caching
            data: {
                "rand": new Date().getTime()
            },
            */
            timeout: 5000
        };
    } else if (type === "POST") {
        ajaxFinal = {
            ...ajaxBase, 
            processData: false,
            contentType: false,
            //contentType: 'application/x-www-form-urlencoded; charset=utf-8',
            //contentType: 'application/json; charset=utf-8',
            //contentType: 'application/pdf',
            data: payload
        };
    }

    try {
        // Putting everything in separate XHR to get a bit more information
        await $.ajax(ajaxFinal);
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
                    text (`You are behind VMware CWS.<br>The IP you have used is ${behindCWStext} which resides in ${geoCity} (± ${geoAccr}km).`, dom_process, "html");
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

function randomId(length) {
    let result           = '';
    let characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for ( let i = 0; i < length; ++i ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const getFormDataSize = (formData) => [...formData].reduce((size, [name, value]) => size + (typeof value === 'string' ? value.length : value.size), 0);

//https://stackoverflow.com/questions/44613818/how-to-send-by-ajax-a-pdf-file-autogenerated
function dataURItoBlob(dataURI) {
    // convert base64/URLEncoded data component to raw binary data held in a string
    var byteString;
    if (dataURI.split(',')[0].indexOf('base64') >= 0)
        byteString = atob(dataURI.split(',')[1]);
    else
        byteString = unescape(dataURI.split(',')[1]);

    // separate out the mime component
    var mimeString = dataURI.split(',')[0].split(':')[1].split(';')[0];

    // write the bytes of the string to a typed array
    var ia = new Uint8Array(byteString.length);
    for (var i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }

    return new Blob([ia], {type:mimeString});
}

async function doTesting(sites) {
    let ret = [];
    for (let i=0; i < sites.length; ++i) {
        const url                     = sites[i].url;
        const expected_code           = sites[i].code;
        const request                 = sites[i].request || "GET";
        //TODO: Support files in the future and not only user input
        let payload                 = null;
        if (request === "POST") {
               const convertTo                    = sites[i].convertTo    || "user"; 
               let paddingPayload = "";
               const strPayload = JSON.stringify(sites[i].form);
               if (convertTo === "user") {
                        paddingPayload = " ".repeat(1024);
                        payload = new FormData();
                        payload.append("text", strPayload);
                        // To trigger VMware DLPs for user-input one needs to have a minimum of 1KB as payload - generating 1KB string and add it to existing content.
                        // TODO: Determine actual size of formData and generate a total of 1KB only. 
                        //payload.append("_random_data_", randomId(1024 - 151 - getFormDataSize(payload))); 
                        //payload.append("_random_data_", randomId(1024)); 
                        payload.append("padding", paddingPayload);
               } else if (convertTo === "pdf") {
                        paddingPayload = " ".repeat(1024*5);
                        let jsPDF = window.jspdf.jsPDF;
                        const pdf = new jsPDF();
                        pdf.text(strPayload,10, 10, {"maxWidth": 200});
                        pdf.text(paddingPayload,10,30, {"maxWidth": 200});
                        let outputBase64 = pdf.output("datauristring");
                        let preBlob = dataURItoBlob(outputBase64);
                        payload = new File([preBlob], "test.pdf", {type: 'application/pdf'});
                        pdf.save("test.pdf");
               }
        }
        const [jqXHR, xhr, rtt, data] = await doAjax(url, {request: request, payload: payload}); 
        let classified              = "";
        let bool                    = false;
        if (expected_code === xhr.status) {
            if (xhr.status === 403) {
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
        ret.push([bool, classified, rtt, url, xhr.status, data]);
    }
    return ret;
}


function lookup(id) {
    for (let i = 0; i < testConfig.length; i++) {
        let o = testConfig[i];
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
    $(".progress-bar").text(`${count}/${sum} (${num}%)` );
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

function createTestPage () {
    let initHTML = `
        <div class="alert" style="display: none" role="alert" id="inner-message">
              <div class="d-flex align-items-center justify-content-between">
                <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Danger:"><use xlink:href="#exclamation-triangle-fill"/></svg>
                <div id="alert_message"></div>
                <button type="button" class="btn-close" aria-label="Close"></button>
              </div>
        </div>
        <div class="row top30">
          <div class="col">
            <div class="card-header-custom d-md-flex align-items-center justify-content-between">
                <h4 class="card-title">Check connectivity and performance of HTTP</h4>
            </div>
            <div class="card-group">
                <div class="card text-center">
                  <div class="card-body">
                    <h4 class="card-title" id="stats_mean">0 s</h4>
                    <p class="card-text">(Average HTTP response time)</p>
                  </div>
                </div>
                <div class="card text-center">
                  <div class="card-body">
                    <h4 class="card-title" id="stats_std">0 s</h4>
                    <p class="card-text">(Standard deviation from HTTP response times)</p>
                  </div>
                </div>
                <div class="card text-center">
                  <div class="card-body">
                    <h4 class="card-title" id="stats_quantitle">0 s</h4>
                    <p class="card-text">(75% | 50% | 25% percentile from HTTP response times)</p>
                  </div>
                </div>
            </div>
            <div class="card-footer-custom d-md-flex align-items-center justify-content-between">
                <p class="card-text" id="cws_process"></p>
                <a href="#" class="btn btn-primary" data-category="cws" id="cws_check">Re-run</a>
            </div>
          </div>
          <div class="col">
             <div class="card invisible">
                  <div class="card-body top4">
                    <p class"card-text"><br></p>
                  </div>
              </div>
              <div class="card">
                  <div class="card-body">
                    <p class"card-text">Successful tests:</p>
                    <div class="progress">
                        <div class="progress-bar bg-success" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                    </div>
                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                        <button class="btn btn-primary top15" type="button" id="test_all">Test All</button>
                    </div>
                  </div>
              </div>
          </div>
        </div>
    `
    $(document.body).append(initHTML);
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
    for (let i = 0; i < testConfig.length; ++i){
        const o = testConfig[i];
        if (!o.isEnabled) { continue };
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
            case "dlp":
            case "cinspect":
                let [howMessage, failMessage, loadMessage, listWebsites] = lookup(id);
                $(footerText).text(loadMessage);
                let asyncFunc = doTesting(listWebsites);
                if (typeof asyncFunc === "object") {
                    Promise.resolve(asyncFunc).then(function(returnValues) {
                        let [isBlocked, data, rtt, url, code, msg] = returnValues[0];
                        if (returnValues.length > 1) {
                            for (let i=1 ; i < returnValues.length; ++i) {
                                let [isOtherBlocked] = returnValues[i];
                                isBlocked = isBlocked && isOtherBlocked; 
                            }
                        }
                        if (isBlocked == true && code >= 100) {
                            $(button).attr("data-tested","blocked");
                            changeButton(button, "Blocked", "success");
                            $(footerText).html(`Category identified by CWS as <strong>${data}</strong>. HTTP response time was <strong>${rtt}s</strong>`);
                        }else if (isBlocked == false && code >= 100) {
                            // Main website got blocked but other domain parts might have a wrong state, as it got blocked not like the test-case intended to.  
                            //TODO: To be more specific on if other URLs really got blocked by CWS or by other security. 
                            if (returnValues[0][0] && returnValues.length > 1) {
                                $(button).attr("data-tested","blocked-differently");
                                changeButton(button, "Blocked but...", "warning");
                                $(bodyText).html(`Several URLs for given test-case are used for testing. The main URL '${url}' got blocked from CWS but the other URLs returned unexpected return HTTP code, which indicates a wrong configuration. Please double check the configuration.`);
                                $(footerText).html(`Category identified by CWS as <strong>${data}</strong>. HTTP response time was <strong>${rtt}s</strong>`);
                            } else {
                                $(button).attr("data-tested","unblocked");
                                changeButton(button, "Unblocked", "danger");
                                $(bodyText).html(failMessage);
                                $(footerText).html(`HTTP response time was <strong>${rtt}s</strong>`);
                            }
                        } else {
                            $(button).attr("data-tested","error");
                            changeButton(button, "Error", "danger");
                            $(bodyText).html("<strong>"+msg+"</strong>");
                            $(footerText).html(`HTTP response time was <strong>${rtt}s</strong>`);
                        }
                        let length = 0;
                        for (var i=testConfig.length; i--;) {
                            if (testConfig[i].isEnabled) {
                                length += 1;
                            }
                        }
                        progressBar(length, $(".btn-outline-success").length);
                    });
                }
                break;
        }
    });
    $('#cws_check').click();
}

function createFaqPage() {
    let initHtml = `
        <div class="row"><br><br></div>
        <div class="container top30">
            <div class="accordion" id="accordionPanels">
            </div>
        </div>
    `;
    $(document.body).append(initHtml);
    for (let i=0; i < faqConfig.length; ++i) { 
       let o = faqConfig[i];
       if (!o.isEnabled) {continue;}
       let div = `
          <div class="accordion-item">
            <h2 class="accordion-header" id="panelsStayOpen-heading${i}">
              <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#panelsStayOpen-collapse${i}" aria-expanded="false" aria-controls="panelsStayOpen-collapse${i}">
                 ${o.title}
              </button>
            </h2>
            <div id="panelsStayOpen-collapse${i}" class="accordion-collapse collapse" aria-labelledby="panelsStayOpen-heading${i}">
              <div class="accordion-body">
                 ${o.detail}
              </div>
            </div>
          </div>
       `; 
       $("#accordionPanels").append(div);
    }
}

function createSpecPage() {
    //https://stackoverflow.com/questions/13686470/how-can-i-convert-numeric-http-status-code-to-its-display-name-in-javascript 
    let friendlyHttpStatus = {
        '200': 'OK',
        '201': 'Created',
        '202': 'Accepted',
        '203': 'Non-Authoritative Information',
        '204': 'No Content',
        '205': 'Reset Content',
        '206': 'Partial Content',
        '300': 'Multiple Choices',
        '301': 'Moved Permanently',
        '302': 'Found',
        '303': 'See Other',
        '304': 'Not Modified',
        '305': 'Use Proxy',
        '306': 'Unused',
        '307': 'Temporary Redirect',
        '400': 'Bad Request',
        '401': 'Unauthorized',
        '402': 'Payment Required',
        '403': 'Forbidden',
        '404': 'Not Found',
        '405': 'Method Not Allowed',
        '406': 'Not Acceptable',
        '407': 'Proxy Authentication Required',
        '408': 'Request Timeout',
        '409': 'Conflict',
        '410': 'Gone',
        '411': 'Length Required',
        '412': 'Precondition Required',
        '413': 'Request Entry Too Large',
        '414': 'Request-URI Too Long',
        '415': 'Unsupported Media Type',
        '416': 'Requested Range Not Satisfiable',
        '417': 'Expectation Failed',
        '418': 'I\'m a teapot',
        '429': 'Too Many Requests',
        '500': 'Internal Server Error',
        '501': 'Not Implemented',
        '502': 'Bad Gateway',
        '503': 'Service Unavailable',
        '504': 'Gateway Timeout',
        '505': 'HTTP Version Not Supported',
    };
    function categoryToHuman (category) {
        for (let i=0; i < existingCategories.length; ++i) {
            let o = existingCategories[i];
            if (o.id === category) {
                return o.humanReadable;
            }
        }
    };
    function descMethod(obj){
      let ret = "<br><br>This is done by calling the following: <br><br>";
      for (let i=0; i < obj.websites.length; ++i) {
         const o = obj.websites[i];
         const request = o.request || "GET";
         let url = o.url;
         if (i >= 1) {
             url = "<strong><sup><a href='#testSpecRef1'>[1]</a></sup></strong> "+o.url;
         }
         ret += `<strong>${url}</strong><br> via a <strong>${request}</strong> method and expecting status <strong>${o.code}(${friendlyHttpStatus[o.code]})</strong> to be returned.`;
         if (request === "POST") {
            ret += `<br>It was send with the following payload: <strong>${JSON.stringify(o.form)}<sup><a href='#testSpecRef2'>[2]</a></sup></strong>`;
         }
         ret += "<br><br>";
      }
      return ret;
    }
    let initHtml = `
        <div class="row"><br><br></div>
        <div class="container-lg top30">
            <table class="table table-striped" id="tableTestSpec">
                <thead class="thead-light"><tr>
                    <th scope="col">Threat</th>
                    <th scope="col">Test Description</th>
                    <th scope="col">Remediation Guidelines</th>
                </tr></thead>
                <tbody>
                </tbody>
            </table>
            <div class="row g-3">
                <span><a name="testSpecRef1"><strong><sup>[1]</sup></strong> There are several security methodologies to remediate breaches. This test tries to evaluate if the 'right' security remediation has been configured by evaluating if only the malicous content has been blocked. That is why several URLs are called with the expectations that some will be reachable but some will get blocked.</span></a>
                <span><a name="testSpecRef2"><strong><sup>[2]</sup></strong> The payload is getting encapsulated in a field called 'text' and passed via webform object.</a></span>            
            </div>
        </div>
    `;
    $(document.body).append(initHtml);
    for (let i=0; i < defaultTestConfig.length; ++i) { 
       const o = defaultTestConfig[i];
       if (!o.isEnabled) { continue };
       const method = descMethod(o);  
       const category = categoryToHuman(o.category);
       //const output = o.how.replace(/(?:[^\s.]+\s+){5}|\./g,'$&\n' );
       let row = `
          <tr>
            <td>${o.title}</td>
            <td>${o.desc} ${method}</td>
            <td><strong>${category}</strong><br><br>${o.how}</td>
          </tr>
       `; 
       $("#tableTestSpec tbody").append(row);
    }
}


function createOptionsPage() {

    let uuid = () => ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,c =>(c^(window.crypto||window.msCrypto).getRandomValues(new Uint8Array(1))[0]&15>>c/4).toString(16));
    function anInput(text) {
        const div = `
           <div class="w-25 col-12 input-group">
                <span class="input-group-text">https://</span>
                <input type="text" class="form-control" aria-describedby="basic-addon3" value="${text}">
            </div>
        `;
        return div;
    } 
    function aWebsite(id, disabled, index=0, url="", code="", request="", span=false) {
        //TODO: Refactor code 
        if (request != "") {
            request = `value="${request}"`;
        }
        if (url != "") {
            url = `value="${url}"`;
        }
        if (code != "") {
           code = `value="${code}"`;
        } else if (index == 0) {
           code = `value="403"`;
        }
        if (index == 0) {
           code += "disabled"
        }
        if (span){
            span = `<span class="input-group-text w-25">URL and expected http status code</span>`;
        } else {
            span = "";
        }
        let message = "";
        if (index == 0){
            message = "Please provide a valid https:// or http:// url and status code of 403 for first status code definition."
        } else {
            message = "Please provide a valid https:// or http:// url and status code between 100-599."
        }
        const div = `
            <div class="input-group mb-4">
                ${span}
                <input type="text" class="form-control" placeholder="GET" aria-label="GET" id="${id}_${index}_request" disabled ${request}>
                <input type="text" class="form-control w-50" placeholder="https://example.com" aria-label="https://example.com" id="${id}_${index}_url" ${disabled} ${url}>
                <input type="text" class="form-control" placeholder="403" aria-label="403" id="${id}_${index}_code" ${disabled} ${code}>
                <div class="invalid-feedback">
                    ${message}
                </div> 
            </div>
        `;
        return div; 
    }
    function rowTest(testObj, arrIndex) {
        // Get object order back after storing it.  
        let objectOrder = {
            "title": null,
            "category": null,
            "websites": null,
            "isEnabled": null,
        }
        testObj = Object.assign(objectOrder, testObj);
        let rowDiv = '<div class="row g-5">';
        const rowId = testObj["property"]+"_"+arrIndex;
        Object.keys(testObj).forEach((key, index) => {
           let colDiv = '';
           //if (key != "title" && key != "category" && key != "websites" && key != "isEnabled") { return };
           const id = rowId+"_"+key;
           //const disabled = ((testObj.property == "system") ? "disabled" : "");
           const disabled = "disabled";
           switch (key) {
                case "websites": 
                    colDiv += `<div class="col-4" id="${id}">`;
                    if (testObj.hasOwnProperty("websites") && testObj.websites.length > 0) {
                        for (let i=0; i<testObj.websites.length; ++i) {
                            try { 
                                let o = testObj.websites[i];
                                let r = o.request || "GET";
                                colDiv += aWebsite(id,disabled,i,o.url,o.code,r);
                            } catch (e) {
                                colDiv += aWebsite(id,disabled,i,"","","");
                            }
                        }
                    } else {
                            colDiv += aWebsite(id,disabled);
                    }
                    colDiv += '</div>';
                    break;
                case "title":
                    colDiv += `<div class="col-4"><input type="text" class="form-control" id="${id}" ${disabled} value="${testObj.title}"></div>`;
                    break;
                case "category":
                    colDiv += `<div class="col-2"><select id="${id}" class="form-select" ${disabled}>`;
                    for (let i=0; i<existingCategories.length; ++i) {
                        let o = existingCategories[i];
                        if (!o.isEnabled) {continue};
                        let selected = ((o.id == testObj.category) ? 'selected="selected"': "");
                        colDiv += `<option value="${o.id}" ${selected}>${o.humanReadable}</option>`;
                    }
                    colDiv += `</select></div>`;
                    break;
                case "isEnabled":
                    //const switchButton = ((testObj.isEnabled) ? "Disable": "Enable");
                    //const colorButton = ((testObj.isEnabled) ? "success": "warning");
                    const checked = ((testObj.isEnabled) ? "checked" : "");
                    if (testObj.property != "system") { 
                        colDiv += `
                            <div class="col-2 form-check">
                                <button type="button" class="btn btn-outline-danger" id='${rowId}_delete'>
                                     <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Save"><use xlink:href="#trash-img"/></svg>
                                </button>
                                <button type="button" class="btn btn-outline-primary" id='${rowId}_edit'>
                                     <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Save"><use xlink:href="#edit-img"/></svg>
                                </button>
                                <div class="form-switch">
                                    <input class="btn form-check-input" type="checkbox" id="${rowId}_switch" ${checked}>
                                </div>
                            </div>
                            `;
                    } else {
                        colDiv += `
                            <div class="col-1 form-check">
                                <div class="form-switch">
                                    <input class="btn form-check-input" type="checkbox" id="${rowId}_switch" ${checked}>
                                </div>
                            </div>
                            `;
                    }
                    break;
           } 
           colDiv += '';
           rowDiv += colDiv;
        });
        rowDiv += '</div>';
        return rowDiv;
    }
    function createListTestingDomains() {
        let returnValue = "";
        // Doing <= to get one add row at the end. 
        for (let i=0; i <= testingDomains.length; ++i) {
            let o = testingDomains[i];
            if (o === undefined) {
                o = "";
            } 
            const div = anInput(o);
            returnValue += div;
        } 
        return returnValue;
    }

    function createListTestConfigs() {
        let returnValue = `
            <div class='row'>
                <div class='col col-4'>Title</div>
                <div class='col col-2'>Category</div>
                <div class='col col-4'>URL and http status code</div>
                <div class='col col-2'>Action</div>
            </div> 
            <div class='row'><br></div>
        `;
        for (let i=0 ; i < testConfig.length; ++i) {
            let o = testConfig[i];
            returnValue += rowTest(o,i);
        }
        
        return returnValue;
    }

    function createTestConfigForm(obj={id: undefined, title: undefined, detail:undefined, websites:undefined, category:undefined, isEnabled:undefined}) {
        
        const category = obj.category || undefined; 
        const id       = obj.id       || uuid();
        const websites = obj.websites || [ {url: "", code: ""} ];
        const detail   = obj.detail   || "";
        const title    = obj.title    || "";
        const isEnabled= obj.isEnabled|| true;

        let options = "";
        let first = false;
        for (let i=0; i<existingCategories.length; ++i) {
            const o = existingCategories[i];
            if (!o.isEnabled) {continue};
            let selected = "";
            if (!category) {
                if (!first){
                    selected="selected";
                    first = true;
                } 
            } else if (category == o.id) {
                selected="selected";
            }
            options += `<option value="${o.id}" ${selected}>${o.humanReadable}</option>`;
        }
    
        let divWebsites = "";
        for (let i=0; i<websites.length; ++i) {
            let r = websites[i].request || "GET";
            divWebsites += aWebsite('websites', '',i, websites[i].url, websites[i].code, r, true);
        }

        const checked = ((isEnabled) ? "checked" : "");

        let returnValue = `
            <form class="needs-validation bottom30" id="${id}" novalidate>
                <div class="row g-3">
                    <div class="form-floating col-md-4">
                        <input type="text" class="form-control" id="title" placeholder="Block Youtube with CASB" value="${title}" required>
                        <label for="title">Title of the test-case</label>
                        <div class="invalid-feedback">
                            Please provide a title for your test-case. 
                        </div> 
                    </div>
                    <div class="form-floating col-md-4">
                        <select id="category" class="form-select">
                            ${options}
                        </select>
                        <label for="category">Categories</label>    
                    </div>
                    <div class="form-check form-switch col-md-2">
                        <input class="form-check-input" type="checkbox" id="isEnabled" ${checked}>
                        <label class="form-check-label" for="isEnabled">Disable/Enable</label>
                    </div>
                </div>
                <div class="row g-3 top5">
                    <div class="form-floating col-md-12">
                        <textarea class="form-control" placeholder="We trying to block YouTube functionality with CASB" id="detail" style="height: 100px" required>${detail}</textarea>
                        <label for="description">Description of the test-case</label>    
                        <div class="invalid-feedback">
                            Please provide some description for your test-case.
                        </div> 
                    </div>
                </div> 
                <div class="row g-3 top5">
                    <div class="form-floating col-md-12" id="websites">
                        ${divWebsites}
                    </div>
                <div>
           </form>
                  
        `;

        return returnValue;

    }

    //TODO: Import Export functionality for testConfig

    const initHtml = `
        <div class="row"><br><br></div>
        <div class="container top30">
           <legend>General Control</legend>
           <div class="row g-3" id="generalControl"></div>
           <hr class="bg-danger border-4 border-top border-black">
           <legend>Current Test-Cases</legend>
           <div id="testConfig"></div>
           <hr class="bg-danger border-4 border-top border-black">
           <legend>Add/Edit Test-Cases</legend>
           <div id="testConfigEdit"></div>
           <hr class="bg-danger border-4 border-top border-black">
           <legend>Configure Domains which Performance are Tested Against</legend>
           <div class="row g-3" id="testingDomains"></div>
        </div>
    `; 
    $(document.body).append(initHtml);

   
    $("#generalControl").append( 
            `
             <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                 <button type="button" class="btn btn-danger" id='restOverallConfiguration'>
                    <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Reset"><use xlink:href="#trash-img"/></svg>
                    Reset configuration
                 </button>
                 <button type="button" class="btn btn-outline-primary" id='showOverallConfiguration'>
                    <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Show"><use xlink:href="#show-img"/></svg>
                    Show configuration
                 </button>
                 <div id="modalTestConfig" class="modal fade">
                    <div class="modal-dialog modal-xl">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Raw Configuration Stored</h5>
                                <button type="button" class="btn close" data-dismiss="modal" id="modalCancelTestConfig"">&times;</button>
                            </div>
                            <div class="modal-body">
                                <form>
                                    <div class="form-group">
                                        <label for="inputComment"></label>
                                        <textarea class="form-control" id="modalInputTestConfig"></textarea>
                                    </div>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-dismiss="modal" id="modalDiscardTestConfig">Discard</button>
                                <button type="button" class="btn btn-primary" id="modalSaveTestConfig">Save</button>
                            </div>
                        </div>
                    </div>
                </div>
             </div>
            `
    );
 
    $("#testingDomains").append(createListTestingDomains());

    const divButtons = `
            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                <button type="button" class="btn btn-success" id='testingDomainsSubmit'>
                <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Save"><use xlink:href="#save-img"/></svg>
                Save domain configuration</button>
                <button type="button" class="btn btn-outline-primary" id='testingDomainsAdd'>
                <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Add"><use xlink:href="#add-img"/></svg>
                Add URL input</button>
            </div>
    `;
    $("#testingDomains").append(divButtons);

    $('#testingDomainsSubmit').on('click', async function() {
        const newTestingDomains = $('#testingDomains input').map(function(){
            //TODO: Implement URL checker to see if user is really inputing URLs. 
            if ($(this).val() !== ""){
                return $(this).val();
            }
        }).get();
        await setStorageData({testingDomains:newTestingDomains});
        displayPage("navConfig"); 
    });
    
    $('#testingDomainsAdd').on('click', function() {
        // Getting all inputs under testingDomains and then get last parent. Reason, getting div's will mean I get the buttons as well, which I do not want.
        $('#testingDomains input').last().parent().after(anInput(""));       
    }); 

    $("#testConfigEdit").append(createTestConfigForm());
    const buttonConfigEdit = `
         <div class="row g-3 top5">
                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                        <button type="button" class="btn btn-success" id='testConfigSubmit'>
                        <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Save"><use xlink:href="#save-img"/></svg>
                        Save test-case</button>
                        <button type="button" class="btn btn-outline-primary" id='addWebsite'>
                        <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Add"><use xlink:href="#add-img"/></svg>
                        Add URL input
                        </button>
                        <button type="button" class="btn btn-outline-primary" id='deleteWebsite'>
                        <svg class="bi flex-shrink-0" width="16" height="16" role="img" aria-label="Delete"><use xlink:href="#trash-img"/></svg>
                        Delete last URL input
                        </button>
                </div>
           </div>
        `;

    $('#testConfigEdit').append(buttonConfigEdit);

    $("#testConfig").append(createListTestConfigs());

    $('#testConfigSubmit').on('click', async function() {

        //https://stackoverflow.com/questions/5717093/check-if-a-javascript-string-is-a-url 
        function validURL(str) {
          var pattern = new RegExp('^(https?:\\/\\/)?'+ // protocol
            '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|'+ // domain name
            '((\\d{1,3}\\.){3}\\d{1,3}))'+ // OR ip (v4) address
            '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // port and path
            '(\\?[;&a-z\\d%_.~+=-]*)?'+ // query string
            '(\\#[-a-z\\d_]*)?$','i'); // fragment locator
          return !!pattern.test(str);
        }

        function toggleValid(id, bool){
            if (!bool) {
                $("#"+id).removeClass("is-valid").addClass("is-invalid");
            } else {
                $("#"+id).removeClass("is-invalid").addClass("is-valid");
            }
        }
             
        let newTestConfig = [...testConfig];
        
        let found = false;

        const id        = $("#testConfigEdit form").attr('id');
        const title     = $("#title").val();
        const detail    = $("#detail").val();
        const category  = $("#category").val();
        const isEnabled = $("#isEnabled").is(':checked');

        let error = false;

        if (title.length == 0) {
            toggleValid("title", false); 
            error = true;
        } else {
            toggleValid("title", true); 
        }

        if (detail.length == 0) {
            toggleValid("detail", false); 
            error = true;
        } else {
            toggleValid("detail", true); 
        }

        let websites = [];
        $("#websites input").each(function(index) {
            let [_, arrIndex, type] = $(this).attr('id').split("_");
            if (websites[arrIndex] === undefined) {
                websites[arrIndex] = {};
            }
            const typeValue = ((type == "code") ? parseInt($(this).val(), 10) : $(this).val());
            
            websites[arrIndex][type] = typeValue;
        }); 

        for (let i=0; i<websites.length; ++i){
            const urlIndex = "websites_"+i+"_url";
            const codeIndex = "websites_"+i+"_code";
            if (websites[i].url.length == 0) {
                toggleValid(urlIndex, false); 
                error = true;
            } else if (!validURL(websites[i].url)){
                toggleValid(urlIndex, false); 
                error = true;
            } else {
                toggleValid(urlIndex, true); 
            }

            if (isNaN(websites[i].code)) {
                toggleValid(codeIndex, false); 
                error = true;
            } else if (i == 0 && websites[i].code != 403){
                toggleValid(codeIndex, false); 
                error = true;
            } else if (websites[i].code < 100 || websites[i].code >= 600) {
                toggleValid(codeIndex, false); 
                error = true;
            } else {
                toggleValid(codeIndex, true); 
            }
        }

        if (error) {
            return 0;
        }

        let newObj = {
                title: title,
                desc: "",
                detail: detail,
                how: "",
                fail: "",
                load: "",
                id: id,
                category: category,
                version: 1,
                property: "user",
                isEnabled: isEnabled,
                websites: [...websites]
        }
        let foundIndex = -1;
        for (let i=0; i < newTestConfig.length; ++i) {
            let o = newTestConfig[i];
            if (o.id == id) {
                 foundIndex = i;
                 break;
            } 
        }  
    
        if (foundIndex != -1) {
            let o = newTestConfig[foundIndex];
            o = Object.assign(o,newObj);
            newTestConfig[foundIndex] = o;
        } else {
            newTestConfig.push(newObj);
        }

        await setStorageData({testConfig: newTestConfig});
        displayPage("navConfig");
     });
     
     $('.btn').on('click', async function() {
         //TODO: Refactor this code a bit better
         const length = $("#websites").find(".input-group").length; 
         if ($(this).attr('id') == "addWebsite") {
             $("#websites").append(aWebsite("websites","",length,"","","GET",true));
         } else if ($(this).attr('id') == "deleteWebsite") {
             if (length-1 > 0){
                $("#websites").children("div:last").remove();
             }  
         } else if ($(this).attr('id') == "restOverallConfiguration") {
            await clearStorageData();
            await setConfig();
            displayPage("navConfig");
         } else if ($(this).attr('id') == "showOverallConfiguration") {
            let str = JSON.stringify(testConfig, undefined, 4);
            $("#modalInputTestConfig").val(str);
            //TODO: Dynamicly change height of textarea based on modal size
            $("#modalInputTestConfig").height("500px");
            $("#modalTestConfig").modal("show");    
         } else if ($(this).attr('id') == "modalSaveTestConfig") {
            let newTestConfig = {};
            try {
                let str = $("#modalInputTestConfig").val();    
                newTestConfig = JSON.parse(str);
            } catch (e) {
                //TODO: Better error handling in the case that newTestConfig not a valid JSON. 
                log(e);
            }

            if (Object.keys(newTestConfig).length !== 0) {
                await setStorageData({testConfig: newTestConfig});
                displayPage("navConfig");
            }
         } else if ($(this).attr('id') === "modalCancelTestConfig" || $(this).attr('id') === "modalDiscardTestConfig") {
             displayPage("navConfig");
         } else {
             let [property, arrIndex, action] = $(this).attr('id').split('_');
             switch(action) {
                case "delete": 
                    testConfig.splice(arrIndex,1);
                    await setStorageData({testConfig: testConfig});
                    displayPage("navConfig");
                    break;
                case "switch":
                    //const buttonText = $(this).text().trim();
                    const checked = $(this).is(':checked');
                    if (!checked) {
                        testConfig[arrIndex].isEnabled = false;
                    } else {
                        testConfig[arrIndex].isEnabled = true;
                    }
                    await setStorageData({testConfig: testConfig});
                    displayPage("navConfig");
                    break;
                case "edit":
                    $("#testConfigEdit form").remove();
                    $(createTestConfigForm(testConfig[arrIndex])).insertBefore($("#testConfigSubmit").parent());
                    break;
             }
         }
     });
}

async function displayPage(page) {
    $('nav').nextAll().remove();
    switch (page) {
        case "navFAQ":
            createFaqPage();
            break;
        case "navSpec":
            createSpecPage();
            break;
        case "navConfig":
            await setConfig();
            createOptionsPage();
            break;
        default:
            await setConfig();
            createTestPage();
            break;
    }
}

const getStorageData = key =>
  new Promise((resolve, reject) =>
    ext.storage.local.get(key, result =>
      ext.runtime.lastError
        ? reject(error(ext.runtime.lastError.message))
        : resolve(result)
    )
  )

const setStorageData = data =>
  new Promise((resolve, reject) =>
    ext.storage.local.set(data, () =>
      ext.runtime.lastError
        ? reject(error(ext.runtime.lastError.message))
        : resolve()
    )
  )

const clearStorageData = key =>
  new Promise((resolve, reject) =>
    ext.storage.local.clear(() =>
      ext.runtime.lastError
        ? reject(error(ext.runtime.lastError.message))
        : resolve()
    )
  )


function getVersion() {
  return new Promise((resolve, reject) => {
    $.getJSON("../manifest.json", data => {
      resolve(data.version);
    }); 
  });
}

async function setConfig() {
    const version = await getVersion();
    
    let stored = await getStorageData('testingDomains');

    if (Object.keys(stored).length === 0) {
        setStorageData({testingDomains: defaultTestingDomains});
        testingDomains = [...defaultTestingDomains];
        log("Stored testingDomains default");
    } else {
        testingDomains = [...stored['testingDomains']];
        log("Retrieved testingDomains");
    }

    stored = await getStorageData('testConfig');

    if (Object.keys(stored).length === 0) {
        //testConfig = [...defaultTestConfig];
        //testConfig = JSON.parse(JSON.stringify(defaultTestConfig));
        //testConfig = defaultTestConfig.slice(0);
        testConfig = defaultTestConfig.map(a => {return {...a}});
        setStorageData({testConfig: testConfig});
        setStorageData({mergedStatus:false});
        setStorageData({storedVersion:version});
        log("Stored testConfig default");
    } else {
        const {mergedStatus}     = await getStorageData('mergedStatus');
        const {storedVersion}    = await getStorageData('storedVersion');
        if (!mergedStatus || storedVersion != version) { 
            let userTestConfig = [];
            for (let i=0; i<stored['testConfig'].length; ++i){
                let o = stored['testConfig'][i];
                if(o.property != "system") {
                    userTestConfig.push(o);
                }
            }
            //testConfig = [...defaultTestConfig.concat(userTestConfig)];
            //testConfig = JSON.parse(JSON.stringify(defaultTestConfig.concat(userTestConfig)));
            //testConfig = defaultTestConfig.concat(userTestConfig).slice(0);
            testConfig = defaultTestConfig.concat(userTestConfig).map(a => {return {...a}});
            setStorageData({testConfig: testConfig});
            setStorageData({mergedStatus:true});
            setStorageData({storedVersion:version});
            log('Merged and stored new testConfig');
        } else {
            //testConfig = [...stored['testConfig']];
            //testConfig = JSON.parse(JSON.stringify(stored['testConfig']));
            //testConfig = stored['testConfig'].slice(0);
            testConfig = stored['testConfig'].map(a => {return {...a}});
            log('Using testConfig Stored');
        }
    }
    log(testConfig);
}

$(function() {
    //TODO: Try to get getVersion() to work here. Await is not working before load.
    $.getJSON("../manifest.json", function (data) { 
        const version = `v${data.version}`;
        let html = $(".navbar-brand").html();
        if (version === "v0.1") {
            version = "beta"
        }
        $(".navbar-brand").html(html+`<small><small><sub>(${version})</sub></small></small>`);   
    });
});

$(window).bind("load", function () {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const page = urlParams.get('page');
    // e.g. vmchecker.tests.html?page=config
    displayPage(page);
    $('.nav-link').on('click', function() {
        const linkClicked = $(this);
        if (!linkClicked.prop('href').includes('#')) { return 0 }; 
        const page = linkClicked.attr('id');
        //const page = linkClicked.text().toLowerCase();
        displayPage(page);
    });
});
