const config = [
    {
        title: "How can I contribute?",
        detail: "Feel free to fork the code and enhance it, test the extension and provide feedback or just give me a star in GitHub - all mechansims help to improve the extension or my motivation &#128521;",
        enable: 1
    },
    {
        title: "What are the prerequisites to successfully test the tests in the extension?",
        detail: `
            As a minimum recommended:<br><br>
            <ul>
                <li>To download and install the <strong>SSL Certification</strong>, so VMware CWS can inspect download/upload traffic.</li>
                <li>Ensure all domains in <code>js/vmchecker.config.js</code> under the variable <code>testing_domains</code> are going through VMware CWS.</li>
                <li>Allow <strong>*.github.com</strong>, <strong>*.github.io</strong> and <strong>api.ipify.org</strong> to reach the internet.</li>
            </ul>
            <br>
            Rather then be specific on which HTTP/HTTPs traffic should or should not go through VMware CWS, I would recommend to send all traffic to VMware CWS for the duration of the testing.

        `,
        enable: 1
    },
    {
        title: "How does 'check connectivity and performance' work?",
        detail: `
            For <strong>connectivity</strong>:<br><br>
                <ul>
                    <li>It checks first your external IP. This done by calling <strong>http://api.ipify.org/</strong> API.</li>
                    <li>Checking if the IP is within a VMware SASE POP definition</li>
                    <li>Tries to reach <strong>https://safe-cws-sase.vmware.com</strong> to double confirm that one is behind CWS</li>
                </ul>
            After confirming the above, it will do a <strong>performance</strong> test:<br><br>
                <ul>
                    <li> It will use the domains defined in the file <code>js/vmchecker.config.js</code> within the variable name <code>testing_domains</code>.</li>
                    <li> It will calculate the response time of each and calculate the total average, std and percentitle statistics.</li>
                </ul>
            <br>
            One can alter the <code>test_domains</code> variable to include or exclude domains for testing. Please only note, adding more domains, will cause more load to your browser.
        `,
        enable: 1
    },
    {
        title: "Are the test performed harmful for my PC?",
        detail: "<strong>No</strong>, the extension uses a simple HTTP GET to evaluate the received response form it.",
        enable: 1
    },
    {
        title: "What does 'Blocked', 'Blocked but...', 'Unblocked or 'Error'  mean after test has been executed?",
        detail: `If test has a state:<br><br>
            <ul>
                <li><strong>Blocked</strong> it means the extension received a HTTP 403 (Forbidden) message from VMware CWS, meaning it got blocked. It double checks that 403 has sent the message.</li>
                <li><strong>Blocked but...</strong> it means the extension received a HTTP 403 (Forbidden) message from VMware CWS for the main url test-case; however, other urls in the test-case received a different HTTP code as expected. For example, the Vimeo test-case under CASB tries to test of if search is getting blocked and if other parts of Vimeo are still working as expectged. If URL filtering is used to block Vimeo then all the urls will not get blocked, which means, yes searching got blocked but everything else as well - which is not what was expected.</li>
                <li><strong>Unblocked</strong> it means the extension received HTTP 200 (OK). Either configuration was not applied correct or the content bypassed CWS.</li>
                <li><strong>Error</strong> it means any other response status which is not 403 or 200 has been received. This could be caused by many factors, e.g. the testing site is unreachable (404) or another security enforcement has protected one. Please try again later and if it occurs again please fill in a ticket.</li>
            </ul>
        `,
        enable: 1
    },
    {
        title: "Can I change the test URLs used?",
        detail: "<strong>Yes</strong>, one can edit the <code>js/vmchecker.config.js</code> to not only alter the URLs but add/delete tests. In the future, I will add a option page to the extension to be able to alter URLs accordingly.",
        enable: 1

    },
    {
        title: "Why is there no phishing test case?",
        detail: "Today the majority of browsers are blocking websites which are considered phishing. As soon as the extension tries to reach such websites, the browser will block it accordingly and display a warning to the user. As such, there is no means for the extension to test VMware CWS configuration. However, one can test it manually by <a href='https://www.phishtank.com/phish_search.php?valid=y&active=y&Search=Search' class='link-primary' target='_blank' rel='noopener'>visting PhishTank</a> and select a website to test from. <strong>CAUTION: This websites can potentially be harmful</strong>",
        enable: 1

    },

]

$(function() {
    $.getJSON("../manifest.json", function (data) { 
        let version = "v"+data.version;
        let html = $(".navbar-brand").html();
        if (version === "v0.1") {
            version = "beta"
        }
        $(".navbar-brand").html(html+`<small><small><sub>(${version})</sub></small></small>`);   
    });
 
    for (let i=0; i < config.length; i++) { 
       let o = config[i];
       if (!o.enable) {
            continue;
       }
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

});

