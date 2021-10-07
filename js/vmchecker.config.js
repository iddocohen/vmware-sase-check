const testing_domains = [
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

const config = [
     { 
       title: "Block acess to proxy avoidance and anonymizers websites",
       desc : "This test tries to connect to a proxy website and download their logo.",
       detail: "Employees often try to bypass company policy by using anonymization/proxy websites that allow them to visit blacklisted websites, view pornography, or access restricted content.",
       how  : "In order to properly enforce company policy, you should configure your security solution to identify and restrict access to anonymizing websites. This can be archived with VMware CWS by selecting <strong>Proxy Avoidance and Anonymous</strong> under the <strong>Web Category</strong> when configuring a new policy under <strong>URL Filtering</strong>.",
       fail : "To properly enforce company policy, set VMware CWS to identify and block anonymizing website access. New anonymizer websites come online each day, so enabling blocking anonymous and proxy websites with VMware CWS you do not need to worry about updating your security infrastructure regularly but still can keep your company data safe and help limit corporate liability.",
       load : "Testing your ability to access anonymizing or proxy websites...",
       id: "block_proxy",
       category: "urlfilter",
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
       how  : "To protect your users/employees from gambling, try select <strong>Gambling</strong> under <strong>Web Category</strong> when configuring a new policy under <strong>URL Filtering</strong>", 
       fail : "Please double check that under <strong>URL Filtering</strong> you are filtering the right category.",
       load : "Testing your ability to download the image from the gambling website...",
       id: "block_gambling",
       category: "urlfilter",
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
       how  : "Filtering adult and pornography sites can be archived with VMware CWS by selecting <strong>Adult and Pornography</strong> under the <strong>Web Category</strong> when configuring a new policy under <strong>URL Filtering</strong>.",
       fail : "Enable proper <strong>URL Filtering</strong> on VMware CWS to detect and block adult websites.",
       load : "Testing for your ability to access adult websites...",
       id: "block_adult",
       category: "urlfilter",
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
        how  : "In order to protect your organisation from spyware and adware, you can use <strong>Threat Categories</strong> under <strong>URL Filtering</strong> to select <strong>Malware</strong>.",
        fail : "The lack of proper security enforcement forcement can permit spyware to continually track user activities and sends this data to third-parties. With proper <strong>URL Filtering</strong> with VMware CWS, this can be avoided.",
        load : "Testing if the browser can reach a popular spyware website...",
        id: "block_spwyware",
        category: "urlfilter",
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
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/4.4/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-light'>here</a>.",
        fail : "To protect your organisations from 0-day or known, malware, spyware and viruse files, VMware CWS <strong>Content Inspection</strong> can be used to identify and block theese automatically.",
        load : "Trying to download the eicar.com file over HTTPs...",
        id: "block_https_malware",
        category: "cinspect",
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
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/4.4/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-light'>here</a>.",
        fail : "To protect your organisations from 0-day or known, malware, spyware and viruse files, VMware CWS <strong>Content Inspection</strong> can be used to identify and block this automatically.",
        load : "Trying to download the eicar.com file over HTTP...",
        id: "block_http_malware",
        category: "cinspect",
        websites: [ 
              {
                url: "http://www.rexswain.com/eicar2.zip",
                code: 403
              }
       ]
     },
     {
        title: "Block malware downloads from well-known cloud providers",
        desc: "This test attempts to download a malware from popular cloud application provider.",
        detail: "Netskope's new report in 2021 found that cloud storage apps account for more than 66% of cloud malware delivery. Cybercriminals deliver malware through cloud apps to bypass and take advantage of any app-specific allow lists.",
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/4.4/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-light'>here</a>.",
        fail : "Organisations can become a potential big target and may face huge losses if, they do not take any effective to block malware from any kind of destination. VMware CWS can help with <strong>Content Inspection</strong> to reduce that risk.",
        load : "Trying to download the malware from AWS...",
        id: "block_cloud_malware",
        category: "cinspect",
        websites: [ 
              {
                url: "https://security-scorecard.s3.us-east-2.amazonaws.com/eicar_com.zip",
                code: 403
              }
       ]
     },
     {
        title: "Block files who have been compromised by exploited",
        desc: "This test checks if you are protected from known file-based exploits.",
        detail: "Exploitation activity is a race against the clock for all parties involved. Attackers are attempting to exploit vulnerabilities before vendors have an opportunity to patch them and to continue exploiting them before the consumer patches them.",
        how  : "If not already done so, enable the <strong>Inspection Engine</strong> first by going under <strong>Policies</strong>. Then create a policy that inspects <strong>Upload</strong> and <strong>Download</strong> for <strong>All files</strong> and <strong>All User Group</strong> and <strong>All Domain/Categories</strong>. Last but not least use <strong>Action</strong> and select <strong>Inspect</strong> to ensure <strong>File Hash Check</strong>, <strong>File Full Scan</strong> and <strong>Sandbox Inspection</strong> are used for fitlering. For more info please visit <a href='https://docs.vmware.com/en/VMware-Cloud-Web-Security/4.4/VMware-Cloud-Web-Security-Configuration-Guide/GUID-A48C9642-A96C-4CC5-90E9-7C5490378661.html' target='_blank' rel='noopener' class='link-light'>here</a>.",
        fail : "Most exploits are attempting to create a backdoor in infected devices that paves the way for additional malware. With VMware CWS <strong>Content Inspection</strong> this zero-day exploits and well-know exploits can be detected and mitigated.",
        load : "Trying to download the pdf file which is exploited...",
        id: "block_file_exploits",
        category: "cinspect",
        websites: [ 
              {
                url: "https://storage.googleapis.com/dummyfile-storage-securityscorecard/PoC-test-pdf.pdf",
                code: 403
              }
       ]
     },
     {
        title: "Not allow searching Video's (example Vimeo)",
        desc: "This test checks if searching videos on Vimeo get blocked and if other functionalities still work.",
        detail: "Vimeo is one of the biggest plaform to share professional video for every device but as YouTube has a huge searchable video base which can motiviate procrastination. The VMware CWS Cloud Access Security Broker (CASB) can be used to allow employees to share companies video footage to Vimeo and in parallel deny browsing the content of Vimeo..",
        how: "",
        fail: "Users will be able to search and look for video's on Vimeo. With the right VMware CWS <strong>CASB</strong> configuration, this can be mitigated.",
        load : "Trying to execute a search in Vimeo...",
        id: "block_vimeo_search",
        category: "casb",
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

export { config, testing_domains};
