# CreeP7M
Small JS library for p7m offline file handling: 
+ extract 
+ verify
+ timestamp check
+ OCSP revocation check

Full offline file handling, your documents never leave your local browser\
\
Under the hood is powered by full featured OpenSSL v3 compiled to WebAssembly.\
Indeed CreeP7M don't use any custom made WebAssembly program or library, just "plain" OpenSSL CLI commands!

## How to
Use <mark>data-cp7m-path</mark> to pass openssl wasm binary path
```javascript
<script src="creep7m.js" data-cp7m-path="openssl"></script>
```
Define your file input with class <mark>cp7m-input</mark>
```
<input class="cp7m-input" type="file" accept=".p7m">
```
Initialize CreeP7M object, constructor accepts url strings to a Trusted List Provider resource
and a cors-proxy service, OCSP responder are not cors enabled so cors-proxy is somehow
a soft requirement
```javascript
const CP7M = new CreeP7M(null, 'https://www.itsbalto.com/f/cors-proxy/?apiurl=');
```
If not provided we use TLP from https://eidas.ec.europa.eu/efda/tl-browser/api/v1/browser/tl/IT
### Default bindings
By default CreeP7M listen for 'click' events on elements with below classes
 exposing almost all methods

| Class          | Action  |
| -------------- | ------- |
| cp7m-input (mandatory)    | File input element to work with    |
| cp7m-extract   | Extract file input     |
| cp7m-verify    | Verify file authenticity and timestamp validity against TSP list |
| cp7m-details   | Get Signer and Issuer details |
| cp7m-ocsp      | OCSP validation against Issuer ocsp responder |
| cp7m-cacheClear| Clear TSP list from default 15 days localStorage cache |

### Events
Basic usage
```javascript
CP7M.addEventListener("cp7mOutput", (e) => console.log(e));
```
By default each method fires an event, you can override this behavior by
calling it with <mark>false</mark>
```javascript
const verifyResult = await CP7M(false);
```
## Build OpenSSL to WebAssembly
A prebuilt binary is already provided but you can build your own
### Download and prepare Emscripten environment
git clone https://github.com/emscripten-core/emsdk.git \
cd emsdk \
./emsdk install latest \
./emsdk activate latest \
source ./emsdk_env.sh \
export CC=emcc \
export CXX=emcc
### Build OpenSSL
git clone -b openssl-3.0 https://github.com/openssl/openssl.git \
cd openssl \
emconfigure ./Configure no-hw no-shared no-asm no-threads no-ssl3 no-dtls no-engine no-dso linux-x32 -static \
sed -i 's/$(CROSS_COMPILE)//' Makefile \
emmake make -j 16 build_generated libssl.a libcrypto.a apps/openssl CFLAGS="-O2 -s ENVIRONMENT='web' -s FILESYSTEM=1 -s MODULARIZE=1 -s EXPORTED_RUNTIME_METHODS=\"['callMain', 'FS', 'TTY']\" -s INVOKE_RUN=0 -s EXIT_RUNTIME=1 -s EXPORT_ES6=0 -s EXPORT_NAME='CreeP7M_openssl' -s USE_ES6_IMPORT_META=0 -s ALLOW_MEMORY_GROWTH=1 -l proxyfs.js"

## A small dive into p7m background
### EU Trust chain
EU Authority delegate management of Trusted Provider (AKA Issuer:entity which provide digital
certificates) List by Country of origin:\
https://ec.europa.eu/tools/lotl/eu-lotl.xml => frome here you can get Providers of each Country\
For example IT = https://eidas.agid.gov.it/TL/TSL-IT.xml \
On below URL we have some API but not CORS enabled so needs to
be cors-proxyed or retrieved server side \
https://eidas.ec.europa.eu/efda/browse

## Credits
https://quoll.it/firma-digitale-p7m-come-estrarre-il-contenuto/ \

## Useful links
https://github.com/emscripten-core/emscripten/blob/main/src/settings.js \
https://www.openssl.org/docs/man3.0/man1/openssl-cms.html \
https://www.agid.gov.it/it/piattaforme/firma-elettronica-qualificata/software-verifica \
https://github.com/esig/dss/blob/master/dss-cookbook/src/main/asciidoc/_chapters/eSignatures-and-dss.adoc#TrustedLists
