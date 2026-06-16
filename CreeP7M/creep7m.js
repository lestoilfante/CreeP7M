//<copyright>
//    Copyright lestoilfante 2023-2026 (https://github.com/lestoilfante)
//    GNU General Public License version 3 (GPLv3)
//</copyright>
class CreeP7M {
    static #CP7M_ELEMENT; //holds file input element
    static #CP7M_MODULE; //holds a cached WebAssembly module already compiled
    static #FS_PATH = '/Creep/'; //Module FS working path
    static #FS_PATH_CA = CreeP7M.#FS_PATH + '_certs_/'; //Module FS trusted CA path
    static #FS_CA_FILE = CreeP7M.#FS_PATH_CA + 'CA.pem'; //Module FS trusted CA file name
    static #MAIN_INSTANCE; //holds 1st called module instance, inner FS will be shared with subsequent instance through PROXYFS
    static #CORS_PROXY; 
    static #TSP_SRC = 'https://eidas.agid.gov.it/TL/TSL-IT.xml'; //trusted CA source (ETSI TS 119 612 XML)
    static #TSP_PEM; //holds CA.pem contents (string)
    static #TSP_INDEX; //holds issuer certs keyed by ski and dn, built lazily from CA.pem
    static #TSP_SERVICES; //holds cert(base64) -> service type(s) map, from the TSL XML
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
        SIGNATURES: 'signatures',
        DEBUG: 'debug'
    }

    #extractButton; #verifyButton; #detailsButton; #ocspButton; #cacheClearButton;
    #process;
    #output = { msg: '', err: '', status: 1000 };
    #eventListeners = {};

    constructor(caSourceUrl, corsProxyUrl) {
        const el = document.querySelector(CreeP7M.#UIBINDINGS.INPUT);
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

    async #opensslRun(moduleInstance, argsString) {
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
        let r = { msg: '', err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                // peel the whole matrioska, download the innermost payload
                const peel = await this.#peelLayers(null, true);
                if (peel && peel.payload) {
                    const fileOut = this.#readFile(peel.payload.path);
                    CreeP7M.#sendFileToBrowser(fileOut, peel.payload.name);
                    this.#process.FS.unlink(peel.payload.path);
                    r = { msg: peel.layers, err: '', status: 0 };
                }
                else
                    r.err = 'unable to extract payload';
            }
        }
        const _ = { ...r };
        this.#sendOutput(_, CreeP7M.#EVENT.EXTRACT);
        return _;
    }
    //
    async verify(event = true) {
        if (!this.fileInput) return;
        let r = { msg: [], err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                // verify every layer at its own signing time, collect per-layer outcome
                const layers = [];
                await this.#peelLayers(async (layerPath, depth) => {
                    let validAtTime = Math.floor(Date.now() / 1000);
                    const ti = await this.#getWasmInstance();
                    if (ti) {
                        const t = await this.#opensslRun(ti, 'asn1parse -inform DER -dlimit 1 -in ' + layerPath);
                        const tm = (t.status === 0) ? t.msg.match(/OBJECT\s+:signingTime.*?UTCTIME\s+:(\d*Z)/s) : null;
                        if (tm) validAtTime = Math.floor(CreeP7M.#utctimeToDate(tm[1]).getTime() / 1000);
                    }
                    const vi = await this.#getWasmInstance();
                    const v = await this.#opensslRun(vi, 'cms -inform DER -in ' + layerPath + ' -verify -attime ' + validAtTime + ' -out -noout -CAfile ' + CreeP7M.#FS_CA_FILE);
                    layers.push({ depth: depth, status: v.status, err: v.err });
                });
                r.msg = layers;
                r.status = (layers.length && layers.every(l => l.status === 0)) ? 0 : 1;
                r.err = layers.filter(l => l.status !== 0).map(l => l.err).join('');
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.VERIFY);
        return _;
    }
    //
    async getDetails(event = true) {
        if (!this.fileInput) return;
        let r = { msg: [], err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                r.msg = await this.#collectSigners(); // flat list, one entry per signer with depth
                r.status = r.msg.length ? 0 : 1;
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.DETAILS);
        return _;
    }
    //
    async getSignatureTimestamp(event = true) {
        if (!this.fileInput) return;
        let r = { msg: [], err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                const signers = await this.#collectSigners();
                r.msg = signers.map(s => s.Timestamp); // one Date per signer, in layer order
                r.status = signers.length ? 0 : 1;
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.TIMESTAMP);
        return _;
    }
    //
    async signatureCount(event = true) {
        if (!this.fileInput) return;
        let r = { msg: 0, err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                // total signers across all matrioska layers
                r.msg = (await this.#collectSigners()).length;
                r.status = 0;
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.SIGNATURES);
        return _;
    }
    //
    async ocspVerify(event = true) {
        if (!this.fileInput) return;
        // since emscripten wasm binary has very limited network access we use openssl offline ocsp verification + fetch
        let r = { msg: [], err: '', status: 1000 };
        try {
            const signers = await this.#collectSigners();
            for (const s of signers) {
                const res = { depth: s.depth, status: 1000, err: '' };
                const issuerCerts = (s.Issuer?.OCSP && s.Signer?.Serial) ? await this.#issuerCerts(s.Issuer.SKI, s.Issuer.DN) : [];
                if (issuerCerts.length) {
                    for (const cert of issuerCerts) {
                        // Define the URL of the OCSP responder
                        const ocspResponderURL = (CreeP7M.#CORS_PROXY) ? CreeP7M.#CORS_PROXY + s.Issuer.OCSP : s.Issuer.OCSP;
                        const certSerial = `0x${s.Signer.Serial}`;
                        const instanceOcspReq = await this.#getWasmInstance();
                        if (!instanceOcspReq) break;
                        const certPem = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
                        const tspCertFile = CreeP7M.#file(this.fileInput.name + '.Issuer.pem');
                        instanceOcspReq.FS.writeFile(tspCertFile, certPem);
                        const ocspReq = CreeP7M.#file(this.fileInput.name + '.ocsp-req.der');
                        // Create an offline ocsp request and save it to file
                        const x = await this.#opensslRun(instanceOcspReq, 'ocsp -nonce -issuer ' + tspCertFile + ' -serial ' + certSerial + ' -reqout ' + ocspReq);
                        if (x.status !== 0) { res.err = x.err; continue; }
                        const ocspReqFile = this.#readFile(ocspReq);
                        // Send the OCSP request to the OCSP responder
                        const response = await fetch(ocspResponderURL, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/ocsp-request', 'Accept': 'application/ocsp-response' },
                            body: ocspReqFile
                        });
                        if (!response.ok) { res.err = 'something wrong with ocsp responder'; continue; }
                        const ocspResponse = await response.arrayBuffer();
                        const ocspRes = CreeP7M.#file(this.fileInput.name + '.ocsp-res.der');
                        this.#writeFile(ocspRes, ocspResponse);
                        const instanceOcspVerify = await this.#getWasmInstance();
                        if (!instanceOcspVerify) break;
                        // Process the OCSP response
                        const y = await this.#opensslRun(instanceOcspVerify, 'ocsp -reqin ' + ocspReq + ' -respin ' + ocspRes + ' -CAfile ' + CreeP7M.#FS_CA_FILE);
                        res.status = y.status; res.err = y.err;
                        if (y.status === 0) break; // first responder success
                    }
                }
                else
                    res.err = 'something went wrong getting certificate details';
                r.msg.push(res);
            }
            r.status = (r.msg.length && r.msg.every(x => x.status === 0)) ? 0 : 1;
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
    async debugP7M(command = 'asn1parse -i -inform DER -dlimit 1', event = true) {
        if (!this.fileInput) return;
        let r = { msg: '', err: '', status: 1000 };
        const instance = await this.#getWasmInstance();
        if (instance) {
            const fileIn = await this.#sendToFSifNotExists(this.fileInput);
            if (fileIn) {
                // drop caller -in/-out (and their values) to keep the virtual FS safe, force -in on current file
                const args = command.split(' ').filter((tok, i, a) => tok !== '-in' && tok !== '-out' && a[i - 1] !== '-in' && a[i - 1] !== '-out');
                args.push('-in', CreeP7M.#file(this.fileInput.name));
                r = await this.#opensslRun(instance, args.join(' '));
            }
        }
        const _ = { ...r };
        if (event) this.#sendOutput(_, CreeP7M.#EVENT.DEBUG);
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

    // Walk nested CMS layers outer->inner, run fn(layerPath, depth) on each (fn may be null).
    // base64-wrapped layers are decoded; processed layers are unlinked, the input is kept.
    // Returns { layers, payload }; payload is the final non-CMS file, freed unless keepPayload
    async #peelLayers(fn, keepPayload = false) {
        const MAX = 10;
        let curPath = CreeP7M.#file(this.fileInput.name);
        let depth = 0;
        while (depth < MAX) {
            if (fn) await fn(curPath, depth);
            const instance = await this.#getWasmInstance();
            if (!instance) return null;
            const outPath = CreeP7M.#file(this.fileInput.name + '.peel' + depth);
            const r = await this.#opensslRun(instance, 'cms -inform DER -in ' + curPath + ' -verify -noverify -binary -out ' + outPath);
            if (depth > 0) try { instance.FS.unlink(curPath); } catch (e) { }
            if (r.status !== 0) {
                try { instance.FS.unlink(outPath); } catch (e) { }
                return { layers: depth, payload: null };
            }
            const bytes = instance.FS.readFile(outPath, { encoding: 'binary' });
            const der = CreeP7M.#base64ToDer(bytes);
            if (der) { // base64 bridge between two signature layers
                instance.FS.unlink(outPath);
                curPath = CreeP7M.#file(this.fileInput.name + '.layer' + depth);
                instance.FS.writeFile(curPath, der, { encoding: 'binary' });
                depth++;
                continue;
            }
            if (CreeP7M.#isCmsSignedData(bytes)) { curPath = outPath; depth++; continue; }
            // non-CMS reached: this is the real payload
            if (!keepPayload) { try { instance.FS.unlink(outPath); } catch (e) { } return { layers: depth + 1, payload: null }; }
            return { layers: depth + 1, payload: { path: outPath, name: this.fileInput.name.replace(/(\.p7m)+$/i, '') } };
        }
        return { layers: depth, payload: null };
    }

    // Collect every signer across all layers, flat with depth
    async #collectSigners() {
        const signers = [];
        await this.#peelLayers(async (layerPath, depth) => {
            signers.push(...await this.#parseSigners(layerPath, depth));
        });
        return signers;
    }

    // Signers of a single CMS layer: match each SignerInfo to its embedded cert by serial
    async #parseSigners(layerPath, depth) {
        const signers = [];
        let instance = await this.#getWasmInstance();
        if (!instance) return signers;
        let r = await this.#opensslRun(instance, 'cms -inform DER -in ' + layerPath + ' -cmsout -print -noout');
        if (r.status !== 0) return signers;
        const print = r.msg;
        instance = await this.#getWasmInstance();
        if (!instance) return signers;
        r = await this.#opensslRun(instance, 'pkcs7 -inform DER -in ' + layerPath + ' -print_certs -text');
        if (r.status !== 0) return signers;
        // index embedded certs by canonical hex serial (Signer.Serial uses #parseCertSerial)
        const certs = {};
        r.msg.split('-----END CERTIFICATE-----').forEach(block => {
            const parsed = CreeP7M.#parseCertificate(block);
            if (parsed.Signer.Serial) certs[parsed.Signer.Serial] = parsed;
        });
        // one signer per sid; pull its serial + signingTime, attach the matching cert
        print.split(/d\.(?:issuerAndSerialNumber|subjectKeyIdentifier):/).slice(1).forEach(chunk => {
            const sn = chunk.match(/serialNumber:\s*(0x[0-9a-fA-F]+|\d+)/); // openssl prints decimal or 0x hex
            const serial = sn ? BigInt(sn[1]).toString(16).toUpperCase() : null; // canonical, matches #parseCertSerial
            const time = (chunk.match(/signingTime[\s\S]*?(?:UTCTIME|GENERALIZEDTIME)\s*:\s*([^\n]+)/) || [])[1];
            const rec = (serial && certs[serial]) ? certs[serial] : { Signer: {}, Issuer: {} };
            rec.depth = depth;
            rec.Timestamp = time ? CreeP7M.#printTimeToDate(time.trim()) : '';
            // enrich issuer from a warm trusted-list index only (null when cold, never triggers a build)
            const issuer = this.#issuerEntries(rec.Issuer.SKI, rec.Issuer.DN)[0];
            rec.Issuer.Serial = (issuer && issuer.serial) ? issuer.serial : null;
            rec.Issuer.NotBefore = (issuer && issuer.notBefore) ? issuer.notBefore : null;
            rec.Issuer.NotAfter = (issuer && issuer.notAfter) ? issuer.notAfter : null;
            rec.Issuer.ServiceTypes = (issuer && issuer.serviceTypes) ? issuer.serviceTypes : null;
            signers.push(rec);
        });
        return signers;
    }

    // Resolve issuer cert(s) from trusted list, by ski then dn fallback (builds index if needed)
    async #issuerCerts(ski, dn) {
        if (!CreeP7M.#TSP_INDEX)
            await this.buildTspIndex();
        return this.#issuerEntries(ski, dn).map(e => e.cert || e); // tolerate legacy string entries
    }

    // Issuer index entries for a ski/dn, only from an already warm index (no build)
    #issuerEntries(ski, dn) {
        const idx = CreeP7M.#TSP_INDEX;
        if (!idx) return [];
        return (ski && idx.ski[ski]) || (dn && idx.dn[dn]) || [];
    }

    // Parse CA.pem once into a ski/dn keyed index of issuer cert entries, persist alongside pem cache.
    // Public so callers can warm it before getDetails() to populate issuer serial/validity
    async buildTspIndex() {
        const bundle = CreeP7M.#file('_tsp_bundle.p7b');
        let instance = await this.#getWasmInstance();
        if (!instance) return null;
        let r = await this.#opensslRun(instance, 'crl2pkcs7 -nocrl -certfile ' + CreeP7M.#FS_CA_FILE + ' -out ' + bundle);
        if (r.status !== 0) { console.error(r); return null; }
        instance = await this.#getWasmInstance();
        if (!instance) return null;
        r = await this.#opensslRun(instance, 'pkcs7 -in ' + bundle + ' -print_certs -text');
        instance.FS.unlink(bundle);
        if (r.status !== 0) { console.error(r); return null; }
        const index = { ski: {}, dn: {} };
        r.msg.split('-----END CERTIFICATE-----').forEach(chunk => {
            const pem = chunk.match(/-----BEGIN CERTIFICATE-----([\s\S]*)$/);
            if (!pem) return;
            const dnMatch = chunk.match(/Subject:\s*(.*?)\n/);
            const dn = dnMatch ? dnMatch[1].split(', ').reverse().join(', ') : null; //same format as parsed Issuer.DN
            const skiMatch = chunk.match(/X509v3 Subject Key Identifier:\s*([0-9A-Fa-f:]+)/);
            const ski = skiMatch ? skiMatch[1] : null;
            const nb = chunk.match(/Not Before\s*:\s*(.*)/);
            const na = chunk.match(/Not After\s*:\s*(.*)/);
            const cert = pem[1].replace(/\s+/g, '');
            const entry = {
                cert: cert,
                serial: CreeP7M.#parseCertSerial(chunk),
                notBefore: nb ? nb[1] : '',
                notAfter: na ? na[1] : '',
                serviceTypes: (CreeP7M.#TSP_SERVICES && CreeP7M.#TSP_SERVICES[cert]) || [] //from the TSL, empty if map not warm
            };
            if (ski) (index.ski[ski] = index.ski[ski] || []).push(entry); //NOTE same key may hold renewed/cross certs
            if (dn) (index.dn[dn] = index.dn[dn] || []).push(entry);
        });
        CreeP7M.#TSP_INDEX = index;
        const dataStore = JSON.parse(localStorage.getItem(CreeP7M.#TSP_CACHE_KEY));
        if (dataStore) {
            dataStore.index = index;
            localStorage.setItem(CreeP7M.#TSP_CACHE_KEY, JSON.stringify(dataStore));
        }
        return index;
    }

    // True if bytes look like a DER CMS SignedData (SEQUENCE + signedData OID near the head)
    static #isCmsSignedData(bytes) {
        if (!bytes || bytes[0] !== 0x30) return false;
        const oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
        for (let i = 1; i < 12 && i + oid.length <= bytes.length; i++) {
            let match = true;
            for (let k = 0; k < oid.length; k++) { if (bytes[i + k] !== oid[k]) { match = false; break; } }
            if (match) return true;
        }
        return false;
    }

    // If bytes are base64 wrapping a CMS, return the decoded DER, else null
    static #base64ToDer(bytes) {
        const txt = new TextDecoder('latin1').decode(bytes).trim();
        if (!txt.length || !/^[A-Za-z0-9+/\s=]+$/.test(txt)) return null;
        try {
            const out = Uint8Array.from(atob(txt.replace(/\s+/g, '')), c => c.charCodeAt(0));
            return CreeP7M.#isCmsSignedData(out) ? out : null;
        } catch (e) { return null; }
    }

    // canonical uppercase hex serial from a cert -text block ("(0x..)", colon-hex or decimal forms)
    static #parseCertSerial(text) {
        let m = text.match(/Serial Number:[^\n(]*\(0x([0-9a-fA-F]+)\)/);
        if (m) return BigInt('0x' + m[1]).toString(16).toUpperCase();
        m = text.match(/Serial Number:\s*\n\s*((?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2})/);
        if (m) return BigInt('0x' + m[1].replace(/:/g, '')).toString(16).toUpperCase();
        m = text.match(/Serial Number:\s*(\d+)/);
        return m ? BigInt(m[1]).toString(16).toUpperCase() : '';
    }

    // openssl prints "Mon D HH:MM:SS YYYY GMT"; reorder so Date parses it reliably
    static #printTimeToDate(s) {
        const m = s.match(/(\w+)\s+(\d+)\s+(\d+:\d+:\d+)\s+(\d+)/);
        return m ? new Date(`${m[1]} ${m[2]} ${m[4]} ${m[3]} UTC`) : '';
    }

    static #parseCertificate(certString) {
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
        const certSnHex = CreeP7M.#parseCertSerial(certString); // handles 0x, colon-hex and decimal forms
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
                Serial: certSnHex,
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

    static #utctimeToDate(utctime) {
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
                CreeP7M.#TSP_INDEX = dataStore.index || null;
                return;
            }
        }
        // Get a new list: fetch direct first, cors-proxy only as fallback
        // (a self-hosted or CORS-enabled list needs no proxy; OCSP still uses it)
        let response = await fetch(CreeP7M.#TSP_SRC).catch(() => null);
        if ((!response || !response.ok) && CreeP7M.#CORS_PROXY)
            response = await fetch(CreeP7M.#CORS_PROXY + CreeP7M.#TSP_SRC).catch(() => null);
        if (!response || !response.ok) {
            console.error('Error fetching CA');
            return;
        }
        await response.text()
            .then((text) => {
                const doc = new DOMParser().parseFromString(text, 'application/xml');
                if (doc.querySelector('parsererror'))
                    throw new Error('TSL XML parse error');
                // only certs bound to a TSP service, skip scheme operator and TL signature;
                // dedup (same cert is listed under several services) and map each to its service type(s)
                const services = {};
                Array.from(doc.getElementsByTagNameNS('*', 'ServiceInformation')).forEach(service => {
                    const typeEl = service.getElementsByTagNameNS('*', 'ServiceTypeIdentifier')[0];
                    const type = typeEl ? typeEl.textContent.trim() : '';
                    Array.from(service.getElementsByTagNameNS('*', 'X509Certificate')).forEach(cert => {
                        const base64 = cert.textContent.replace(/\s+/g, '');
                        if (!base64) return;
                        const types = services[base64] || (services[base64] = []);
                        if (type && !types.includes(type)) types.push(type);
                    });
                });
                let pemCertificates = '';
                Object.keys(services).forEach(base64 => {
                    pemCertificates += `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
                });
                CreeP7M.#TSP_PEM = pemCertificates;
                CreeP7M.#TSP_SERVICES = services;
                const dataStore = JSON.stringify({ date: new Date(), pem: pemCertificates });
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

    // Human label for an ETSI TS 119 612 service type URI (falls back to the stripped suffix)
    static describeServiceType(uri) {
        const key = (uri || '').replace('http://uri.etsi.org/TrstSvc/Svctype/', '');
        const map = {
            'CA/QC': 'Qualified certificate CA',
            'CA/PKC': 'Public key certificate CA',
            'NationalRootCA-QC': 'National root CA (qualified)',
            'RootCA-QC': 'Root CA (qualified)',
            'Certstatus/OCSP': 'OCSP responder',
            'Certstatus/OCSP/QC': 'OCSP responder (qualified)',
            'Certstatus/CRL': 'CRL issuer',
            'Certstatus/CRL/QC': 'CRL issuer (qualified)',
            'TSA': 'Time-stamping authority',
            'TSA/QTST': 'Qualified time-stamp service',
            'TSA/TSS-QC': 'Time-stamp service for qualified certs',
            'TSA/TSS-AdESQCandQES': 'Time-stamp service for AdES/QES',
            'EDS': 'Electronic delivery service',
            'EDS/Q': 'Qualified electronic delivery',
            'EDS/REM': 'Registered electronic mail',
            'EDS/REM/Q': 'Qualified registered electronic mail',
            'PSES': 'Preservation service for e-signatures',
            'PSES/Q': 'Qualified preservation service',
            'QESValidation': 'Validation service for QES',
            'QESValidation/Q': 'Qualified validation service for QES',
            'RA': 'Registration authority',
            'RA/nothavingPKIid': 'Registration authority',
            'ACA': 'Attribute certificate authority',
            'SignaturePolicyAuthority': 'Signature policy authority',
            'Archiv': 'Archival service',
            'Archiv/nothavingPKIid': 'Archival service',
            'IdV': 'Identity verification',
            'IdV/nothavingPKIid': 'Identity verification',
            'KEscrow': 'Key escrow service',
            'KEscrow/nothavingPKIid': 'Key escrow service',
            'PP': 'Identity provider',
            'TLIssuer': 'Trusted list issuer',
            'RemoteQSigCDManagement': 'Remote qualified signature device mgmt',
            'RemoteQSealCDManagement': 'Remote qualified seal device mgmt',
            'unspecified': 'Unspecified service'
        };
        return map[key] || key || '';
    }
}
