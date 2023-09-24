class CreeP7M {
    static #CP7M_ELEMENT; //holds file input element
    static #CP7M_MODULE; //holds a cached WebAssembly module already compiled
    static #FS_PATH = '/Creep/'; //Module FS working path
    static #FS_PATH_CA = CreeP7M.#FS_PATH + '_certs_/'; //Module FS trusted CA path
    static #FS_CA_FILE = CreeP7M.#FS_PATH_CA + 'CA.pem'; //Module FS trusted CA file name
    static #MAIN_INSTANCE; //holds 1st called module instance, inner FS will be shared with subsequent instance through PROXYFS
    static #CORS_PROXY; 
    static #TSP_SRC = 'https://eidas.ec.europa.eu/efda/tl-browser/api/v1/browser/tl/IT'; //trusted CA source
    static #TSP_PEM; //holds CA.pem contents (string)
    static #TSP_LIST; //holds CAs 
    static #TSP_CACHE_KEY = 'CP7M_Certificates'; //localStorage key for CA cache
    static #TSP_CACHE_DAYS = 15; //localStorage CA cache expiration
    static #PATH; //path to emscripten wasm module, provided by script attribute "data-cp7m-path"
    static #UIBINDINGS = {
        INPUT: '.cp7m-input',
        EXTRACT: '.cp7m-extract',
        VERIFY: '.cp7m-verify',
        DETAILS: '.cp7m-details',
        OCSP: '.cp7m-ocsp',
        CACHECLEAR: '.cp7m-cacheClear'
    };
    static #EVENT = {
        EXTRACT: 'extract',
        VERIFY: 'verify',
        DETAILS: 'details',
        TIMESTAMP: 'timestamp',
        OCSP: 'ocsp',
        DEBUG: 'debug'
    }

    #extractButton; #verifyButton; #detailsButton; #ocspButton; #cacheClearButton;
    #process;
    #output = { msg: '', err: '', status: 1000 };
    #eventListeners = {};

    constructor(caSourceUrl, corsProxyUrl) {
        const el = document.querySelector('.cp7m-input');
        if (!CreeP7M.#CP7M_ELEMENT && el) {
            CreeP7M.#CP7M_ELEMENT = el;
            // Parse URL args
            CreeP7M.#TSP_SRC = (caSourceUrl) ? caSourceUrl : CreeP7M.#TSP_SRC;
            CreeP7M.#CORS_PROXY = (corsProxyUrl) ? corsProxyUrl : CreeP7M.#CORS_PROXY;
            // Load Emscripten module
            const scriptElement = document.querySelector('script[data-cp7m-path]');
            const scriptPath = (scriptElement) ? scriptElement.dataset.cp7mPath : '';
            const fullPath = scriptPath.endsWith('/') ? scriptPath : scriptPath + '/';
            CreeP7M.#PATH = new URL(fullPath, window.location);
            const script = document.createElement('script');
            script.src = `${CreeP7M.#PATH}openssl.js`; // Path to Emscripten-generated module
            document.body.appendChild(script);
            // Get CAs
            if (!CreeP7M.#TSP_PEM) {
                CreeP7M.#fetchCAs();
            }
            // UI bindings
            this.#extractButton = document.querySelector(CreeP7M.#UIBINDINGS.EXTRACT);
            if (this.#extractButton)
                this.#extractButton.addEventListener('click', (e) => this.extract());
            this.#verifyButton = document.querySelector(CreeP7M.#UIBINDINGS.VERIFY);
            if (this.#verifyButton)
                this.#verifyButton.addEventListener('click', (e) => this.verify());
            this.#detailsButton = document.querySelector(CreeP7M.#UIBINDINGS.DETAILS);
            if (this.#detailsButton)
                this.#detailsButton.addEventListener('click', (e) => this.getDetails());
            this.#ocspButton = document.querySelector(CreeP7M.#UIBINDINGS.OCSP);
            if (this.#ocspButton)
                this.#ocspButton.addEventListener('click', (e) => this.ocspVerify());
            this.#cacheClearButton = document.querySelector(CreeP7M.#UIBINDINGS.CACHECLEAR);
            if (this.#cacheClearButton)
                this.#cacheClearButton.addEventListener('click', (e) => CreeP7M.cacheClear());
        }

    }
    // Some Getter
    get fileInput() {
        return CreeP7M.#CP7M_ELEMENT ? CreeP7M.#CP7M_ELEMENT.files[0] : null;
    }
    get #listFiles() {
        return this.#process.FS.readdir(CreeP7M.#FS_PATH);
    }
    get TSP_SRC() {
        return CreeP7M.#TSP_SRC;
    }
    get TSP_AGE() {
        const dataStore = JSON.parse(localStorage.getItem(CreeP7M.#TSP_CACHE_KEY));
        if (dataStore && dataStore.date)
            return new Date(dataStore.date);
        else return null;
    }

    async #getWasmInstance() {
        if (!this.fileInput) {
            console.error('no file selected');
            return null;
        }
        const output = this.#output;
        const options = {
            'instantiateWasm': CreeP7M.#instantiateCachedWasm,
            'print': function (text) { output.msg += text + '\n' },
            'printErr': function (text) { output.err += text + '\n' }
        };
        // Mount MAIN_INSTANCE FS_PATH as shared on subsequent instances
        if (!CreeP7M.#MAIN_INSTANCE) {
            CreeP7M.#MAIN_INSTANCE = await CreeP7M_openssl(options);
            CreeP7M.#MAIN_INSTANCE.FS.mkdir(CreeP7M.#FS_PATH);
            CreeP7M.#MAIN_INSTANCE.FS.mkdir(CreeP7M.#FS_PATH_CA);
            CreeP7M.#MAIN_INSTANCE.FS.writeFile(CreeP7M.#FS_CA_FILE, CreeP7M.#TSP_PEM); // add CAs file on 1st run
            this.#process = CreeP7M.#MAIN_INSTANCE;
        }
        else {
            this.#process = await CreeP7M_openssl(options);
            this.#process.FS.mkdir(CreeP7M.#FS_PATH);
            this.#process.FS.mount(this.#process.FS.filesystems.PROXYFS, {
                root: CreeP7M.#FS_PATH,
                fs: CreeP7M.#MAIN_INSTANCE.FS
            }, CreeP7M.#FS_PATH);
        }
        return this.#process;
    }

    //
    async opensslRun(moduleInstance, argsString) {
        //NOTE openssl result message is always written to stderr
        this.#output.msg = '';
        this.#output.err = '';
        this.#output.status = 1000;
        const args = argsString.split(' ');
        this.#output.status = await moduleInstance.callMain(args);
        return this.#output;
    }

    // 
    async extract() {
        if (!this.fileInput) return;
        let r;
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                const fileOutName = this.fileInput.name.replace(/\.p7m$/i, '');
                const fileOutFullPath = CreeP7M.#file(fileOutName);
                r = await this.opensslRun(instance, 'cms -inform DER -in ' + CreeP7M.#file(this.fileInput.name) + ' -verify -noverify -binary -out ' + fileOutFullPath);
                if (r.status === 0) {
                    const fileOut = this.#readFile(fileOutFullPath);
                    CreeP7M.#sendFileToBrowser(fileOut, fileOutName);
                    instance.FS.unlink(fileOutFullPath);
                }
            }
        }
        const _ = { ...r };
        this.#sendOutput(_, CreeP7M.#EVENT.EXTRACT);
        return _;
    }
    //
    async verify(event = true) {
        if (!this.fileInput) return;
        let r;
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                const timestamp = await this.getSignatureTimestamp(false);
                const validAtTime = (timestamp && timestamp.status === 0) ? Math.floor(timestamp.msg.getTime() / 1000) : Math.floor(Date.now() / 1000);
                r = await this.opensslRun(instance, 'cms -inform DER -in ' + CreeP7M.#file(this.fileInput.name) + ' -verify -attime ' + validAtTime + ' -out -noout -CAfile ' + CreeP7M.#FS_CA_FILE);
                if (r.status !== 0) {
                    console.error(r);
                }
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.VERIFY);
        return _;
    }
    //
    async getDetails(event = true) {
        if (!this.fileInput) return;
        let r;
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                const certFile = CreeP7M.#file(this.fileInput.name + '.pem');
                r = await this.opensslRun(instance, 'pkcs7 -inform DER -in ' + CreeP7M.#file(this.fileInput.name) + ' -print_certs -text -out ' + certFile);
                if (r.status === 0) {
                    const contents = instance.FS.readFile(certFile, { encoding: 'utf8' });
                    const details = CreeP7M.parseCertificate(contents);
                    const timestamp = await this.getSignatureTimestamp(false);
                    details.Signer.Timestamp = (timestamp && timestamp.status === 0) ? timestamp.msg : '';
                    if (details.Issuer.DN) {
                        details.Issuer.Certs = CreeP7M.#TSP_LIST.providers.filter(x => x.dn === details.Issuer.DN).map(x => x.cert); //NOTE TSP_LIST may have multiple certs with same DN
                        if (!details.Issuer.Certs.length) //NOTE dn sometimes is differently formatted, try to use SKI if no dn found 
                            details.Issuer.Certs = CreeP7M.#TSP_LIST.providers.filter(x => x.ski === details.Issuer.SKI).map(x => x.cert);;
                    }
                    r.msg = details;
                }
                else
                    console.error(r);
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.DETAILS);
        return _;
    }
    //
    async getSignatureTimestamp(event = true) {
        if (!this.fileInput) return;
        let r;
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                r = await this.opensslRun(instance, 'asn1parse -inform DER -dlimit 1 -in ' + CreeP7M.#file(this.fileInput.name));
                if (r.status === 0) {
                    const timestampMatch = r.msg.match(/OBJECT\s+:signingTime.*?UTCTIME\s+:(\d*Z)/s);
                    const timestamp = timestampMatch ? CreeP7M.utctimeToDate(timestampMatch[1]) : null;
                    r.msg = timestamp;
                }
                else
                    console.error(r.err);
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.TIMESTAMP);
        return _;
    }
    //
    async ocspVerify(event = true) {
        if (!this.fileInput) return;
        // since emscripten wasm binary has very limited network access we use openssl offline ocsp verification + fetch
        let r = { msg: '', err: '', status: 1000 };
        try {
            const d = await this.getDetails(false);
            if (d.status === 0 && d.msg.Issuer?.DN && d.msg.Issuer?.OCSP && d.msg.Signer?.Serial && d.msg.Issuer?.Certs?.length) {
                for (const cert of d.msg.Issuer.Certs) {
                    // Define the URL of the OCSP responder
                    const ocspResponderURL = (CreeP7M.#CORS_PROXY) ? CreeP7M.#CORS_PROXY + d.msg.Issuer.OCSP : d.msg.Issuer.OCSP;
                    const certSerial = d.msg.Signer.Serial;
                    const instanceOcspReq = await this.#getWasmInstance();
                    if (instanceOcspReq) {
                        const certPem = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
                        const tspCertFile = CreeP7M.#file(this.fileInput.name + '.Issuer.pem');
                        instanceOcspReq.FS.writeFile(tspCertFile, certPem);
                        const ocspReq = CreeP7M.#file(this.fileInput.name + '.ocsp-req.der');
                        // Create an offline ocsp request and save it to file
                        const x = await this.opensslRun(instanceOcspReq, 'ocsp -nonce -issuer ' + tspCertFile + ' -serial ' + certSerial + ' -reqout ' + ocspReq);
                        if (x.status !== 0)
                            throw new Error(x.err);
                        const ocspReqFile = this.#readFile(ocspReq);
                        const headers = {
                            'Content-Type': 'application/ocsp-request',
                            'Accept': 'application/ocsp-response'
                        };
                        // Send the OCSP request to the OCSP responder
                        const response = await fetch(ocspResponderURL, {
                            method: 'POST',
                            headers: headers,
                            body: ocspReqFile
                        });
                        if (!response.ok)
                            throw new Error('something wrong with ocsp responder');
                        const ocspResponse = await response.arrayBuffer();
                        const ocspRes = CreeP7M.#file(this.fileInput.name + '.ocsp-res.der');
                        this.#writeFile(ocspRes, ocspResponse);
                        const instanceOcspVerify = await this.#getWasmInstance();
                        if (instanceOcspVerify) {
                            // Process the OCSP response
                            const y = await this.opensslRun(instanceOcspVerify, 'ocsp -reqin ' + ocspReq + ' -respin ' + ocspRes + ' -CAfile ' + CreeP7M.#FS_CA_FILE);
                            if (y.status !== 0)
                                throw new Error(y.err);
                            r = y;
                            break; // exit loop on 1st ocsp success
                        }
                    }
                }
            }
            else
                r.err = 'something went wrong getting certificate details';
        }
        catch (e) {
            r.err = e
            console.error(r);
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.OCSP);
        return _;
    }
    //
    async debugP7M() {
        if (!this.fileInput) return;
        let r = { msg: '', err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                r = await this.opensslRun(instance, 'asn1parse -i -inform DER -dlimit 1 -in ' + CreeP7M.#file(this.fileInput.name));
            }
        }
        const _ = { ...r };
        this.#sendOutput(_, CreeP7M.#EVENT.DEBUG);
        return _;
    }

    // Event handling 
    addEventListener(eventType, callback) {
        if (!this.#eventListeners[eventType]) {
            this.#eventListeners[eventType] = [];
        }
        this.#eventListeners[eventType].push(callback);
    }
    #dispatchEvent(eventType, eventData) {
        const callbacks = this.#eventListeners[eventType];
        if (callbacks) {
            callbacks.forEach(callback => callback(eventData));
        }
    }
    #sendOutput(v, cmd) {
        this.#dispatchEvent('cp7mOutput', {
            result: v,
            subject: cmd
        });
    }

    async #sendToFSifNotExists(fileInput) {
        // return if already present
        const oldFile = (this.#process.FS.analyzePath(CreeP7M.#file(fileInput.name)).exists) ? this.#process.FS.stat(CreeP7M.#file(fileInput.name)) : null;
        if (oldFile && oldFile.mtime) {
            const fileDateOld = Date.parse(oldFile.mtime) / 1000; // /1000 needed coz FS api always return milliseconds as 000
            const fileDateNew = parseInt(fileInput.lastModified / 1000);
            if (fileDateOld === fileDateNew) {
                return true;
            }
        }
        // Read the file content asynchronously
        const fileContent = await CreeP7M.#readFileAsync(fileInput);
        if (this.#writeFile(CreeP7M.#file(fileInput.name), fileContent)) {
            // preserve mtime to its original value
            this.#process.FS.utime(CreeP7M.#file(fileInput.name), fileInput.lastModified, fileInput.lastModified)
            return true;
        }
        return false;
    }

    #writeFile(filePath, fileContent) {
        try {
            // Convert the file content to a Uint8Array
            var fileData = new Uint8Array(fileContent);
            // Use Emscripten's FS API to write the file
            this.#process.FS.writeFile(filePath, fileData, { encoding: "binary" });
            return true;
        } catch (e) {
            console.error("Error writing file:", e);
            return false;
        }
    }

    #readFile(filePath) {
        return this.#process.FS.readFile(filePath, { encoding: "binary" });
    }

    static parseCertificate(certString) {
        //(C)
        const countryMatch = certString.match(/Subject:.*?C=([^\/,]*)/);
        const country = countryMatch ? countryMatch[1].replace(/^.*:/, '') : '';
        //(OU)
        const ouMatch = certString.match(/Subject:.*?O=([^\/,]*)/);
        const ou = ouMatch ? ouMatch[1].replace(/^.*:/, '') : '';
        //(CN)
        const cnMatch = certString.match(/Subject:.*?CN=(.*?)[\n\/]/);
        const cn = cnMatch ? cnMatch[1] : '';
        //(SN)
        const snMatch = certString.match(/Subject:.*?serialNumber=([^\/,]*)/);
        const cf = snMatch ? snMatch[1] : '';
        //(Email)
        const emailMatch = certString.match(/X509v3 Subject Alternative Name:\s+email:([^\s]+)/);
        const email = emailMatch ? emailMatch[1] : '';
        //(Certificate SN)
        const certSnMatch = certString.match(/Serial Number:\s.*?([0-9a-fA-F:]+)\s/);
        const certSnHex = certSnMatch ? certSnMatch[1].replace(/:/g, '') : '';
        const certSnDecimal = BigInt(`0x${certSnHex}`).toString();
        //(Certificate Validity Dates)
        const notBeforeMatch = certString.match(/Not Before\s*:\s*(.*)/);
        const notBefore = notBeforeMatch ? notBeforeMatch[1] : '';
        const notAfterMatch = certString.match(/Not After\s*:\s*(.*)/);
        const notAfter = notAfterMatch ? notAfterMatch[1] : '';
        //(Issuer DN)
        const iDnMatch = certString.match(/Issuer:\s*(.*?)\n/);
        const iDn = iDnMatch ? iDnMatch[1].split(', ').reverse().join(', ') : '';
        //(Issuer Key Identifier)
        const ikiMatch = certString.match(/X509v3 Authority Key Identifier:\s*(?:keyid:)?([0-9A-Fa-f:]+)/);
        const iki = ikiMatch ? ikiMatch[1] : '';
        //(Issuer CRL)
        const crlUrisMatch = certString.match(/URI:([^\n\r]+.crl)/);
        const crlUris = crlUrisMatch ? crlUrisMatch[1] : '';
        //(Issuer OCSP)
        const ocspUrisMatch = certString.match(/OCSP.*URI:(.*?)\s/);
        const ocspUris = ocspUrisMatch ? ocspUrisMatch[1] : '';

        const output = {
            Signer: {
                C: country,
                OU: ou,
                CN: cn,
                SN: cf,
                Contact: email,
                Serial: certSnDecimal,
                NotBefore: notBefore,
                NotAfter: notAfter
            },
            Issuer: {
                DN: iDn,
                SKI: iki,
                CRL: crlUris,
                OCSP: ocspUris
            }
        }

        return output;
    }

    static utctimeToDate(utctime) {
        // Assuming that 00-49 represents 2000-2049 and 50-99 represents 1950-1999
        const yearPrefix = parseInt(utctime.slice(0, 2), 10);
        const year = yearPrefix < 50 ? 2000 + yearPrefix : 1900 + yearPrefix;
        const month = parseInt(utctime.slice(2, 4), 10);
        const day = parseInt(utctime.slice(4, 6), 10);
        const hour = parseInt(utctime.slice(6, 8), 10);
        const minute = parseInt(utctime.slice(8, 10), 10);
        const second = parseInt(utctime.slice(10, 12), 10);

        // Create a JavaScript Date object with the extracted components
        return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
    }

    static async #readFileAsync(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = function (event) {
                const fileContent = event.target.result;
                resolve(fileContent); // Resolve the Promise with the content
            };
            reader.onerror = function (event) {
                reject(event.target.error); // Reject the Promise if there's an error
            };

            reader.readAsArrayBuffer(file);
        });
    }

    static #sendFileToBrowser(file, fileName = "donwload.txt") {
        const outFile = new Blob([file], { type: CreeP7M.#getMime(fileName) });
        const url = URL.createObjectURL(outFile);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        link.click();
        URL.revokeObjectURL(url);
    }

    static #getMime(fileName) {
        let mimeType = 'application/octet-stream'; // Default to binary data
        if (fileName.indexOf('.') === -1)
            return mimeType;
        const extension = fileName.slice(fileName.lastIndexOf('.') + 1).toLowerCase();
        switch (extension) {
            case 'pdf': // PDF
                mimeType = 'application/pdf';
                break;
            case 'zip': // ZIP
                mimeType = 'application/zip';
                break;
            case 'xml': // XML
                mimeType = 'application/xml';
                break;
        }
        return mimeType;
    }

    static #file(fileName) {
        return CreeP7M.#FS_PATH + fileName.replace(/ /g, '_');
    }

    static #instantiateCachedWasm(imports, successCallback) {
        if (CreeP7M.#CP7M_MODULE) {
            // If the module is already cached, use it for instantiation
            WebAssembly.instantiate(CreeP7M.#CP7M_MODULE, imports)
                .then((instance) => {
                    successCallback(instance);
                }).catch(function (e) {
                    console.error('wasm instantiation failed! ' + e);
                });
            return {};
        }
        else {
            fetch(`${CreeP7M.#PATH}openssl.wasm`)
                .then(response => response.arrayBuffer())
                .then((wasmBinary) => {
                    WebAssembly.instantiate(new Uint8Array(wasmBinary), imports).then((output) => {
                        CreeP7M.#CP7M_MODULE = output.module; // Cache the module
                        successCallback(output.instance);
                    }).catch(function (e) {
                        console.error('wasm instantiation failed! ' + e);
                    });
                });
            return {};
        }
    }

    static async #fetchCAs() {
        // Look for a cached version
        const dataStore = JSON.parse(localStorage.getItem(CreeP7M.#TSP_CACHE_KEY));
        if (dataStore && dataStore.pem) {
            const lastDate = new Date(dataStore.date);
            const currentDate = new Date();
            const differenceInMilliseconds = currentDate - lastDate;
            const differenceInDays = differenceInMilliseconds / 86400000;
            // Check if the difference is less than cache period
            if (differenceInDays < CreeP7M.#TSP_CACHE_DAYS) {
                CreeP7M.#TSP_PEM = dataStore.pem;
                CreeP7M.#TSP_LIST = dataStore.tsp;
                return;
            }
        }
        // Get a new list
        const tspUrl = (CreeP7M.#CORS_PROXY) ? CreeP7M.#CORS_PROXY + CreeP7M.#TSP_SRC : CreeP7M.#TSP_SRC;
        await fetch(tspUrl)
            .then((response) => response.text())
            .then((text) => {
                const jsonData = JSON.parse(text);
                var pemCertificates = '';
                const tspList = { providers: [] };
                jsonData.serviceProviders.forEach(provider => {
                    provider.services.forEach(service => {
                        service.digitalIdentity.certificates.forEach(certificate => {
                            if (certificate.base64 && certificate.subject) {
                                tspList.providers.push({
                                    dn: certificate.subject,
                                    cert: certificate.base64,
                                    //store key identifier as hex in same format of openssl parsed value
                                    ski: (certificate.skiB64) ? Array.from(atob(certificate.skiB64), byte => byte.charCodeAt(0).toString(16).padStart(2, '0')).join(':').toUpperCase() : null
                                })
                                pemCertificates += `-----BEGIN CERTIFICATE-----\n${certificate.base64}\n-----END CERTIFICATE-----\n`;
                            }
                        });
                    });
                });
                CreeP7M.#TSP_PEM = pemCertificates;
                CreeP7M.#TSP_LIST = tspList;
                const dataStore = JSON.stringify({ date: new Date(), pem: pemCertificates, tsp: tspList });
                // Store the JSON string in local storage
                localStorage.setItem(CreeP7M.#TSP_CACHE_KEY, dataStore);
            }).catch(function (e) {
                console.error(`Error fetching or processing CA: ${e.message}`);
            });
    }
    static cacheClear() {
        localStorage.removeItem(CreeP7M.#TSP_CACHE_KEY);
        //NOTE TSP are still in memory, reload page for a fresh start
    }
}
