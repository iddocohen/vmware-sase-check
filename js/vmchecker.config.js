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
       desc: "This test attempts to visit a known adult website and download a icon. Failing this test means you have not configured to block 'Adult and Pornography' under 'Web Category'.",
       id: "block_adult",
       category: "website",
       website: "https://static-hw.xvideos.com/v3/img/skins/default/favicon.ico"
     },
     {
        title: "Block spyware and adware",
        desc: "This test attempts to download spyware. Failing this test means you have not configured to block 'Spyware and Adware' under 'Web Category'.",
        id: "block_spwyware",
        category: "website",
        website: "https://counter.yadro.ru/id127/ddp-id.gif"
     },
     {
        title: "Block malware over HTTPs",
        desc: "This test attempts to download malware over HTTPs",
        id: "block_https_malware",
        category: "website",
        website: "https://secure.eicar.org/eicar.com"
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

export { config, testing_domains};
