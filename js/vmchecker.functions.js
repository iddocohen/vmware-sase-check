var log = console.log.bind(console);

function getUrl (url) {
    return $.ajax({ 
            type:"GET",
            url:url,
            cache: false,
            async: false,
            dataType: 'html'
     });
}

var check = [
    "https://safe-cws-sase.vmware.com/code.vmware.com/home", 
    "https://safe-cws-sase.vmware.com/sase.vmware.com"
];

function checkCWS() {
    $('.text').text('Testing connection towards VMware Cloud Web Security (CWS) . . .');
    var xhr = new XMLHttpRequest();
    $.ajax({
            type:"GET",
            url:"https://safe-cws-sase.vmware.com/",
            // Will add timestamps behind the URL to ensure cache is not hitting. 
            cache: false,
            // Putting everything in separte XHR to get a bit more information
            xhr: function() {
                return xhr;
            },
            dataType: 'html'
     }).always(function(result){ 
        let t = "Plugin is not working as it should. Please raise a issue under GitHub repository.";
        if (xhr) {
            // We should get vmware.com or cws site. If not behind CWS, will get redirected to vmware.com and if we are behind it we will reach it directly.
            if (xhr.status == 200) {
                if (xhr.responseURL.includes('www.vmware.com')) { // If we get vmware.com then we got redirected, as we are not behind CWS.
                    t = "The response received indicates you are not behind VMware CWS service";
                } else if (xhr.responseURL.includes('safe-cws-sase.vmware.com')) { // We double check that we get a response via CWS
                    $.when(getUrl(check[0]), getUrl(check[1])).done(function(ret1, ret2) { // We checking other vmware websites but behind cws.
                        //TODO: Check if they get blocked by rule, then they are also valid.
                        if (ret1[1] == "success" && ret2[2] == "success"){
                            t = "You are behind VMware CWS but code.vmware.com and sase.vmware.com was not reachable behind CWS.";
                        } else {
                            t = "You are behind VMware CWS and everything works.";
                        }
                    });
                } else { // If neither of the above has happenend, then something has changed the responsURL before reaching the extension.
                    t = "CWS request was changed to '"+xhr.responseURL+"'. This will cause CWS not to work in your environment";
                }
            } else {
                t = "CWS is not reachable. Please try again later."
            }
        }
        $('.text').text(t);
    });
}

$(function () {
    $('.btn').click(function() {
        checkCWS();    
    });
});

