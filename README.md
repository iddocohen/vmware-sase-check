<p align="center">
  <img src="src/icon/icon128-white.png" width="75" height="75"/>
</p>

<h1 align="center">VMware Cloud Web Security (CWS) Checker</h1>

*VMware CWS Checker is a web browser extension to help check your security with (or even without) VMware CWS service*

<img src="screenshot/Overview-google.png?raw=true" alt="Overview of VMware CWS Checker">

## Releases

- Unstable:
    - current main repository
- Stable for Chrome, Firefox and Edge: 
    - [v0.21](https://github.com/iddocohen/vmware-sase-check/releases/tag/v0.21) 

**Please note:** Latest extension standards uses manifest v3. It ensures better security and quicker development turnaround. Unfortunately Firefox and Edge do not support it yet. Until they do, please use older version of code for Firefox/Edge use-case. For all new features, please consider to use Chrome.

## Roadmap
[Please visit the Trello page](https://trello.com/b/yEeXfNJv/vmware-cws-checker-roadmap)

## Getting Started
### Chrome version 92+ 

[On web store](https://chrome.google.com/webstore/detail/vmware-cws-checker/aaahmofhpokmcblajnpgledopdmaedfl)

Or via:

1. Download this repo as stable release listed above or newer changes via [ZIP file from GitHub](https://github.com/iddocohen/vmware-sase-check/archive/refs/heads/main.zip).
2. Unzip the file and you should have a folder named `vmware-sase-check-<version name here>` when downloading a release or `vmware-sase-check-main`.
3. In Chrome go to the extensions page (`chrome://extensions`).
4. Enable Developer Mode.
5. Drag the `vmware-sase-check-main` folder anywhere on the page to import it (do not delete the folder afterwards).
6. Click then on the extension icon (on the top right corner) and pin the new plugin (so you can see it all the time). 

**Notes**
* Every time you open Chrome it may warn you about running extensions in developer mode, just click &#10005; to keep the extension enabled.

### Firefox

1. Download this repo as stable release listed above.
2. Unzip the file and you should have a folder named `vmware-sase-check-<version name here>`.
3. Open Firefox
4. Enter 'about:debugging' in the URL bar
5. Click 'This Firefox'
6. Click 'Load Temporary Add-on'
7. Open the extension's directory and select manifest.json.

### Edge
1. Download this repo as stable release listed above.
2. Unzip the file and you should have a folder named `vmware-sase-check-<version name here>`.
3. In Edge enable developer mode by going to 'about:flags' and check box 'Enable extension developer features'.
4. Restart Edge.
5. Click on Settings (icon with ...).
6. Click on Extension.
7. Use 'Load Extension' and select the whole folder.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

or 

Leave a GitHub star on the top right. 

## Licence
MIT, see ``LICENSE``


