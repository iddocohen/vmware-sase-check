/*
 * VMware CWS Checker - Config File for the Extension
 *
 * Iddo Cohen, September 2021
 *
 * Copyright (C) 2021, Iddo Cohen
 * SPDX-License-Identifier: MIT License
 */

const defaultTestingDomains = [
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

const existingCategories = [
    { id: "casb",       humanReadable: "Cloud Access Security Broker (CASB)", isEnabled: true },
    { id: "dlp",        humanReadable: "Data Loss Prevention (DLP)",          isEnabled: true },
    { id: "urlfilter",  humanReadable: "URL Filtering",                       isEnabled: true},
    { id: "cinspect",   humanReadable: "Content Inspection",                  isEnabled: true },
]

const defaultTestConfig = [
     { 
       title: "Block access to proxy avoidance and anonymizers websites",
       desc : "This test tries to connect to a proxy website and download their logo.",
       detail: "Employees often try to bypass company policy by using anonymization/proxy websites that allow them to visit blacklisted websites, view pornography, or access restricted content.",
       how  : "In order to properly enforce company policy, you should configure your security solution to identify and restrict access to anonymizing websites. This can be archived with VMware CWS by selecting <strong>Proxy Avoidance and Anonymous</strong> under the <strong>Web Category</strong> to block if configuring a new policy under <strong>URL Filtering</strong>.",
       fail : "To properly enforce company policy, set VMware CWS to identify and block anonymizing website access. New anonymizer websites come online each day, so enabling blocking anonymous and proxy websites with VMware CWS you do not need to worry about updating your security infrastructure regularly but still can keep your company data safe and help limit corporate liability.",
       load : "Testing your ability to access anonymizing or proxy websites...",
       id: "block_proxy",
       category: "urlfilter",
       version: 1,
       property: "system",
       isEnabled: true,
       websites: [ 
              {
                url: "https://www.proxysite.com/assets/images/logo.png",
                code: 403
              }
       ]
     },
     { 
       title: "Block access to websites with gambling content",
       desc: "This test tries to connect to a popular gambling website and see if the logo is downloadable.",
       detail : "Gambling problems can happen to anyone from any walk of life and can become  unhealthy obsession with serious consequences. Companies should ensure that their employees cannot access such websites.",
       how  : "To protect your users/employees from gambling, select <strong>Gambling</strong> under <strong>Web Category</strong> for blocking if configuring a new policy under <strong>URL Filtering</strong>.", 
       fail : "Please double check that under <strong>URL Filtering</strong> you are filtering the right category.",
       load : "Testing your ability to download the image from the gambling website...",
       id: "block_gambling",
       category: "urlfilter",
       version: 1,
       property: "system",
       isEnabled: true,
       websites: [ 
              {
                url: "https://www.bet365.com/sports-assets/sports/FooterModule/assets/bet365-logo.svg",
                code: 403
              }
       ]
     },
     { 
       title: "Block access to adult and pornography content",
       desc: "This test attempts to visit a known adult website and download a icon.",
       detail: "It’s clearly wrong for employees to view or share explicit images or videos at your workplace. It puts your company in the difficult position to explain how you allowed that content on your network, and shared via email, instant message, or social media post.",
       how  : "Filtering adult and pornography sites can be archived with VMware CWS by selecting <strong>Adult and Pornography</strong> under the <strong>Web Category</strong> if configuring a new policy under <strong>URL Filtering</strong>.",
       fail : "Enable proper <strong>URL Filtering</strong> on VMware CWS to detect and block adult websites.",
       load : "Testing for your ability to access adult websites...",
       id: "block_adult",
       category: "urlfilter",
       version: 1,
       property: "system",
       isEnabled: true,
       websites: [ 
              {
                url: "https://static-hw.xvideos.com/v3/img/skins/default/favicon.ico",
                code: 403
              }
       ]
     },
     {
        title: "Block access to websites with spyware and adware content",
        desc: "This test attempts to download a image from such a spyware website.",
        detail: "Spyware is a type of malware that steals sensitive information from unknowing users. The effects of spyware range from gathering usage habits for marketing purposes to targeted attacks by nation-states against political activists.",
        how  : "In order to protect your organization from spyware and adware, you can use <strong>Threat Categories</strong> under <strong>URL Filtering</strong> to select <strong>Malware</strong> for blocking.",
        fail : "The lack of proper security enforcement forcement can permit spyware to continually track user activities and sends this data to third-parties. With proper <strong>URL Filtering</strong> with VMware CWS, this can be avoided.",
        load : "Testing if the browser can reach a popular spyware website...",
        id: "block_spyware",
        category: "urlfilter",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                url: "https://counter.yadro.ru/id127/ddp-id.gif",
                code: 403
              }
       ]
     },
     {
        title: "Block malware files over HTTPs",
        desc: "This test tries to download the well known EICAR file over HTTPS to check if it gets blocked.",
        detail: "The damages that an organization may experience as a victim of malware can be listed as, data breaches, illegal removal of balance from bank accounts and unauthorized access to valuable files/documents.",
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/5.0/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-primary'>here</a>.",
        fail : "To protect your organisations from 0-day or known, malware, spyware and virus files, VMware CWS <strong>Content Inspection</strong> can be used to identify and block these automatically.",
        load : "Trying to download the eicar.com file over HTTPs...",
        id: "block_https_malware",
        category: "cinspect",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                url: "https://secure.eicar.org/eicar.com",
                code: 403
              }
       ]
     },
     {
        title: "Block malware files over HTTP",
        desc: "This test tries to download the well known EICAR file over HTTP to check if it gets blocked.",
        detail:"Malware is a very powerful software that is a threat to the corporate organizations. The easy targets of malware are the multinational organizations. Primarily, organizations will face huge complications and internal damages if they fall prey to malware virus.",
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/5.0/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-primary'>here</a>.",
        fail : "To protect your organizations from 0-day or known, malware, spyware and virus files, VMware CWS <strong>Content Inspection</strong> can be used to identify and block this automatically.",
        load : "Trying to download the eicar.com file over HTTP...",
        id: "block_http_malware",
        category: "cinspect",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                url: "http://www.rexswain.com/eicar2.zip",
                code: 403
              },
              {
                url: "http://www.rexswain.com/",
                code: 200
              }
       ]
     },
     {
        title: "Block malware downloads from well-known cloud providers",
        desc: "This test attempts to download a malware from popular cloud application provider.",
        detail: "Netskope's new report in 2021 found that cloud storage apps account for more than 66% of cloud malware delivery. Cybercriminals deliver malware through cloud apps to bypass and take advantage of any app-specific allow lists.",
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/5.0/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-primary'>here</a>.",
        fail : "Organizations can become a potential big target and may face huge losses if, they do not take any effective to block malware from any kind of destination. VMware CWS can help with <strong>Content Inspection</strong> to reduce that risk.",
        load : "Trying to download the malware from AWS...",
        id: "block_cloud_malware",
        category: "cinspect",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                url: "https://security-scorecard.s3.us-east-2.amazonaws.com/eicar_com.zip",
                code: 403
              },
               {
                url: "https://security-scorecard.s3.us-east-2.amazonaws.com/",
                code: 200
              }
       ]
     },
     {
        title: "Block files who have been compromised by exploited",
        desc: "This test checks if you are protected from known file-based exploits.",
        detail: "Exploitation activity is a race against the clock for all parties involved. Attackers are attempting to exploit vulnerabilities before vendors have an opportunity to patch them and to continue exploiting them before the consumer patches them.",
        how  : "If not already done so, isEnabled the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/5.0/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-primary'>here</a>.",
        fail : "Most exploits are attempting to create a backdoor in infected devices that paves the way for additional malware. With VMware CWS <strong>Content Inspection</strong> this zero-day exploits and well-know exploits can be detected and mitigated.",
        load : "Trying to download the pdf file which is exploited...",
        id: "block_file_exploits",
        category: "cinspect",
        version: 1,
        property: "system",
        isEnabled: false,
        websites: [ 
              {
                url: "https://storage.googleapis.com/dummyfile-storage-securityscorecard/PoC-test-pdf.pdf",
                code: 403
              },
              {
                url: "https://storage.googleapis.com/",
                code: 400
              }
       ]
     },
     {
        title: "Block credit card exfiltration encrypted over SSL",
        desc: "Data Loss Prevention helps businesses follow industry regulations and protect sensitive information. It also prevents inadvertent disclosure. Sensitive information that you need to prevent leaking outside your organization includes financial data, such as credit card numbers, social security numbers, or health records.",
        detail: "This test tries to exfiltrate numbers out of your network that match the format of credit card numbers. In addition, this test validates whether SSL inspection is enabled. Your network security solution should identify this encrypted data leakage.",
        how: "To ensure sensitive data does not get leaked, go to <strong>DLP</strong> under the <strong>Security Policies</strong> of choice, select <strong>Add Rule</strong>, select <strong>All User Groups</strong> in step1, select <strong>Inspect Text Input</strong> in step 2, <strong>All Domains and Categories</strong> in step 3, choose the directory <strong>Credit card numbers [Global]</strong> in step 4 and <strong>Block</strong> in step 5.",
        fail: "A large share of all data security breach incidents involve non-malicious company insiders. In fact, Ponemon's \"2013 Cost of Data Breach Study: Global Analysis\" revealed that an astounding 35% of data security breaches in 2012 were simply caused by negligent employees or contractors. VMware CWS with DLP can ensure sensitive information (like credit cards) do not get exposed outside your organisation.",
        load : "Trying to send credit card numbers over https...",
        id: "block_credit_card_over_ssl",
        category: "dlp",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                request: "POST",
                form: [
                    {
                        "k1": "4929-3813-3266-4295",
                        "k2": "5370-4638-8881-3020",
                        "k3": "4916-4811-5814-8111"
                    }
                ],
                url: "https://httpbin.org/post",
                code: 403
              }, 
              {
                request: "POST",
                form: [],
                url: "https://httpbin.org/post",
                code: 200
              }
       ]
     },
     {
        title: "Block credit card exfiltration",
        desc: "Data Loss Prevention helps businesses follow industry regulations and protect sensitive information. It also prevents inadvertent disclosure. Sensitive information that you need to prevent leaking outside your organization includes financial data, such as credit card numbers, social security numbers, or health records.",
        detail: "This test tries to exfiltrate numbers out of your network that match the format of credit card numbers. Your network security solution should identify this encrypted data leakage.",
        how: "To ensure sensitive data does not get leaked, go to <strong>DLP</strong> under the <strong>Security Policies</strong> of choice, select <strong>Add Rule</strong>, select <strong>All User Groups</strong> in step1, select <strong>Inspect Text Input</strong> in step 2, <strong>All Domains and Categories</strong> in step 3, choose the directory <strong>Credit card numbers [Global]</strong> in step 4 and <strong>Block</strong> in step 5.",
        fail: "A large share of all data security breach incidents involve non-malicious company insiders. In fact, Ponemon's \"2013 Cost of Data Breach Study: Global Analysis\" revealed that an astounding 35% of data security breaches in 2012 were simply caused by negligent employees or contractors. VMware CWS with DLP can ensure sensitive information (like credit cards) do not get exposed outside your organisation.",
        load : "Trying to send credit card numbers over http...",
        id: "block_credit_card",
        category: "dlp",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                request: "POST",
                form: [
                    {
                        "k1": "4929-3813-3266-4295",
                        "k2": "5370-4638-8881-3020",
                        "k3": "4916-4811-5814-8111"
                    }
                ],
                url: "http://httpbin.org/post",
                code: 403
              }, 
              {
                request: "POST",
                form: [],
                url: "http://httpbin.org/post",
                code: 200
              }
       ]
     },
     {
        title: "Block social security number exfiltration in Germany over SSL",
        desc: "Data Loss Prevention helps businesses follow industry regulations and protect sensitive information. It also prevents inadvertent disclosure. Sensitive information that you need to prevent leaking outside your organization includes financial data, such as credit card numbers, social security numbers, or health records.",
        detail: "This test tries to exfiltrate numbers out of your network that match the format of Social Security Number in Germany (Sozialversicherungsnummer). In addition, this test validates whether SSL inspection is enabled. Your network security solution should identify this encrypted data leakage.",
        how: "To ensure sensitive data does not get leaked, go to <strong>DLP</strong> under the <strong>Security Policies</strong> of choice, select <strong>Add Rule</strong>, select <strong>All User Groups</strong> in step1, select <strong>Inspect Text Input</strong> in step 2, <strong>All Domains and Categories</strong> in step 3, choose the directory <strong>Credit card numbers [Global]</strong> in step 4 and <strong>Block</strong> in step 5.",
        fail: "",
        load : "Trying to send social security numbers over https...",
        id: "block_ssn_germany",
        category: "dlp",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [ 
              {
                request: "POST",
                form: [
                    {
                        "name": "Günter Müller",
                        "sno": "12-190367-K-05-6",
                    },
                    {
                        "name": "Günter Müller",
                        "sno": "12 190367 K 05 6",
                    },
                    {
                        "name": "Peter Meier",
                        "sno": "66150872P080",
                    },
                    {
                        "name": "Christian Schmidt",
                        "sno": "12 123456 M 123"
                    }
                ],
                url: "https://httpbin.org/post",
                code: 403
              }, 
              {
                request: "POST",
                form: [],
                url: "https://httpbin.org/post",
                code: 200
              }
       ]
     },

     {
        title: "Not allow searching Video's (example Vimeo)",
        desc: "This test checks if searching videos on Vimeo get blocked and if other functionalities still work.",
        detail: "Vimeo is one of the biggest platform to share professional video for every device but as YouTube has a huge search able video base which can motivate procrastination. The VMware CWS Cloud Access Security Broker (CASB) can be used to allow employees to share companies video footage to Vimeo and in parallel deny browsing the content of Vimeo..",
        how: "Under <strong>CASB</strong> in VMware CWS, use <strong>Add Rule</strong>, select <strong>All Users and Groups</strong> for source, select <strong>Vimeo</strong> under <strong>Custom Selection</strong>, choose <strong>Allow</strong> under <strong>Browser Action</strong> and choose <strong>Search</strong> to be <strong>Blocked</strong> only.",
        fail: "Users will be able to search and look for video's on Vimeo. With the right VMware CWS <strong>CASB</strong> configuration, this can be mitigated.",
        load : "Trying to execute a search in Vimeo...",
        id: "block_vimeo_search",
        category: "casb",
        version: 1,
        property: "system",
        isEnabled: true,
        websites: [
            {
                url: "https://vimeo.com/search?q=test", 
                code: 403  
            },
            {
                url: "https://vimeo.com/", 
                code: 200 
            },
            {
                url: "https://vimeo.com/473446147",
                code: 200
            }
        ]
     } 

];

const faqConfig = [
    {
        title: "How can I contribute?",
        detail: "Feel free to fork the code and enhance it, test the extension and provide feedback or just give me a star in GitHub - all mechanisms help to improve the extension or my motivation &#128521;",
        isEnabled: true
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
        isEnabled: true
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
                    <li> It will calculate the response time of each and calculate the total average, std and percentile statistics.</li>
                </ul>
            <br>
            One can alter the <code>test_domains</code> variable to include or exclude domains for testing. Please only note, adding more domains, will cause more load to your browser.
        `,
        isEnabled: true
    },
    {
        title: "Are the test performed harmful for my PC?",
        detail: "<strong>No</strong>, the extension uses a simple HTTP GET to evaluate the received response form it.",
        isEnabled: true
    },
    {
        title: "What does 'Blocked', 'Blocked but...', 'Unblocked or 'Error'  mean after test has been executed?",
        detail: `If test has a state:<br><br>
            <ul>
                <li><strong>Blocked</strong> it means the extension received a HTTP 403 (Forbidden) message from VMware CWS, meaning it got blocked. It double checks that 403 has been received as a message from VMWare CWS.</li>
                <li><strong>Blocked but...</strong> it means the extension received a HTTP 403 (Forbidden) message from VMware CWS for the main url test-case; however, other urls in the test-case received a different HTTP code as expected. For example, the Vimeo test-case under CASB tries to test of if search is getting blocked and if other parts of Vimeo are still working as expectged. If URL filtering is used to block Vimeo then all the urls will not get blocked, which means, yes searching got blocked but everything else as well - which is not what was expected.</li>
                <li><strong>Unblocked</strong> it means the extension received HTTP 200 (OK). Either configuration was not applied correct or the content bypassed CWS.</li>
                <li><strong>Error</strong> it means any other response status which is not 403 or 200 has been received. This could be caused by many factors, e.g. the testing site is unreachable or another security enforcement has protected one. Please try again later and if it occurs again please fill in a ticket.</li>
            </ul>
        `,
        isEnabled: true
    },
    {
        title: "Can I change the test URLs used?",
        detail: "<strong>Yes</strong>, please use the extension 'Config' page to do such.",
        isEnabled: true

    },
    {
        title: "Why is there no phishing test case?",
        detail: "Today the majority of browsers are blocking websites which are considered phishing. As soon as the extension tries to reach such websites, the browser will block it accordingly and display a warning to the user. As such, there is no means for the extension to test VMware CWS configuration. However, one can test it manually by <a href='https://www.phishtank.com/phish_search.php?valid=y&active=y&Search=Search' class='link-primary' target='_blank' rel='noopener'>visting PhishTank</a> and select a website to test from. <strong>CAUTION: This websites can potentially be harmful</strong>",
        isEnabled: true

    },

]

const apis = [
  'alarms',
  'action',
  'bookmarks',
  'browserAction',
  'commands',
  'contextMenus',
  'cookies',
  'downloads',
  'events',
  'extension',
  'extensionTypes',
  'history',
  'i18n',
  'idle',
  'notifications',
  'pageAction',
  'runtime',
  'storage',
  'tabs',
  'webNavigation',
  'webRequest',
  'windows',
]

function Extension () {
  const _this = this;

  apis.forEach(function (api) {

    _this[api] = null;

    try {
      if (chrome[api]) {
        _this[api] = chrome[api];
      }
    } catch (e) {}

    try {
      if (window[api]) {
        _this[api] = window[api];
      }
    } catch (e) {}

    try {
      if (browser[api]) {
        _this[api] = browser[api];
      }
    } catch (e) {}
    try {
      _this.api = browser.extension[api];
    } catch (e) {}
  })

  try {
    if (browser && browser.runtime) {
      this.runtime = browser.runtime;
    }
  } catch (e) {}

  try {
    if (browser && browser.browserAction) {
      this.browserAction = browser.browserAction;
    }
  } catch (e) {}

  try {
    if (browser && browser.action) {
      this.action = browser.action;
    }
  } catch (e) {}

}

let ext = new Extension();

export { ext, faqConfig,  defaultTestConfig, defaultTestingDomains, existingCategories};
