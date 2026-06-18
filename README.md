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
Use `data-cp7m-path` to pass openssl wasm binary path
```javascript
<script src="creep7m.js" data-cp7m-path="openssl"></script>
```
Define your file input with class `cp7m-input`
```
<input class="cp7m-input" type="file" accept=".p7m">
```
Initialize CreeP7M object, constructor accepts url strings to a Trusted List Provider resource
and a cors-proxy service, OCSP responder are not cors enabled so cors-proxy is somehow
a soft requirement
```javascript
const CP7M = new CreeP7M(null, 'https://www.itsbalto.com/f/cors-proxy/?apiurl=');
```
If not provided we use TLP from https://eidas.agid.gov.it/TL/TSL-IT.xml \
The Trusted List source must be an ETSI TS 119 612 XML list.\
A full working example is in [examples](examples/CreeP7M.html)

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

### Methods
All methods are async and resolve to a result object (see below).
Each fires a `process` event then a `cp7mOutput` result event; pass `false` as the
`event` argument to any method to skip both.

| Method | result.msg | Action |
| ------ | ---------- | ------ |
| extract(event) | layer count | peel every signature layer, download the innermost payload |
| verify(event) | per-layer results | verify each layer at its own signing time against TSP list |
| getDetails(event) | signer array | Signer and Issuer details, one entry per signer across all layers |
| getSignatureTimestamp(event) | Date array | signing time per signer |
| signatureCount(event) | number | total signers across all layers |
| ocspVerify(event) | per-signer results | OCSP revocation check for each signer |
| verifyEidas(event) | per-signer assessment | technical verify + eIDAS qualification per signer (cert QcStatements + trusted-list qualifiers; partial TS 119 615, warms the index); **not** a legal determination — see disclaimer |
| buildTspIndex(event) | index | build/warm the trusted-list issuer index; call before getDetails() to populate issuer serial/validity |
| CreeP7M.describeServiceType(uri) | label | static; human label for an ETSI service type URI (e.g. `…/CA/QC` → "Qualified certificate CA") |
| CreeP7M.describeCertPolicy(oid) | label | static; human label for a certificate policy OID (e.g. `0.4.0.194112.1.2` → "Qualified certificate for e-signature, QSCD (natural person)") |
| debugP7M(command, event) | openssl output | run any openssl command against the loaded file (caller `-in`/`-out` stripped, `-in` forced on it); defaults to an asn1parse dump |
| CreeP7M.cacheClear() | - | clear cached TSP list (static; reload page for a fresh fetch) |

### Result
Every method resolves to
```javascript
{ msg, err, status }
```
+ `status` 0 means success (verify/ocspVerify: only if every layer/signer succeeded)
+ NOTE openssl writes its result message to `err` (stderr), not msg
+ nested ("matrioska") signatures are peeled automatically; results cover every layer, tagged with `depth` (0 = outermost)
+ getDetails: msg is an array, one entry per signer
```javascript
[{
    depth,
    Signer: { C, OU, CN, SN, Contact, Serial, NotBefore, NotAfter, Policies, KeyUsage, Qc },
    Issuer: { DN, SKI, CRL, OCSP, Serial, NotBefore, NotAfter, ServiceTypes },
    Timestamp
}]
```
+ Issuer `Serial`/`NotBefore`/`NotAfter`/`ServiceTypes` come from the trusted-list index and are `null` unless it is warm; call `buildTspIndex()` (or run `ocspVerify()`) first to populate them. `ServiceTypes` is the ETSI service type URI(s) the issuer is listed under (e.g. `…/Svctype/CA/QC`)
+ Signer `Policies` is the cert's `X509v3 Certificate Policies` OIDs (the CA-asserted purpose, e.g. qualified e-signature/e-seal, QSCD); translate with `describeCertPolicy`
+ Signer `KeyUsage` is the cert's `X509v3 Key Usage` values (e.g. `["Digital Signature","Non Repudiation"]`)
+ Signer `Qc` is the eIDAS `QcStatements` read from the cert: `{ compliant, qscd, types }` — `compliant` = declared qualified, `qscd` = key in a QSCD, `types` = array of declared uses (`esign`/`eseal`/`web`). These are the cert's own (CA-asserted) claims; an authoritative qualified determination also needs the trusted-list service qualifiers (not yet applied)
+ getSignatureTimestamp: msg is an array of Date, one per signer
+ signatureCount: msg is the total signer count
+ verify / ocspVerify: msg is a per-layer / per-signer array `[{ depth, status, err }]`
+ verifyEidas: msg is a per-signer array of the getDetails entry plus an `Eidas` field `{ verified, issuerQualifiedService, serviceGranted, qualified, qscd, types, assessment }`. `verified` is the technical result; `qualified`/`qscd`/`types` combine the cert `QcStatements` with the trusted-list service qualifiers (`Qualifications`/`CriteriaList`). `status` 0 iff every layer verifies technically. **Partial ETSI TS 119 615**: current service status only (no history), `otherCriteria` not evaluated, and reference time is the self-asserted `signingTime` (qualified timestamp-token not validated) — see the legal disclaimer

### Getters
| Getter | Value |
| ------ | ----- |
| fileInput | currently selected File, or null |
| TSP_SRC | Trusted List source url in use |
| TSP_AGE | Date the cached TSP list was stored, or null |

### Events
Basic usage
```javascript
CP7M.addEventListener("cp7mOutput", (e) => console.log(e));
```
The event payload is
```javascript
{ result, subject }
```
where `result` is the result object above and `subject` is one of
extract | verify | details | timestamp | signatures | ocsp | index | eidas | debug \
By default each method fires an event, you can override this behavior by
calling it with `false`
```javascript
const verifyResult = await CP7M.verify(false);
```
Before doing its work each method first fires a `process` event (`subject: "process"`,
`result.msg` = the upcoming subject, `result.status` 1000 = pending). This lets a UI show a
busy state on `process` and clear it / render on the matching result event, from one listener
```javascript
CP7M.addEventListener("cp7mOutput", (e) => {
    if (e.subject === "process") showBusy();   // e.result.msg = which operation
    else { hideBusy(); render(e); }            // actual result
});
```
The `process` event is suppressed together with its result event when a method is called with `false`.

### Notes
+ Only the first `new CreeP7M()` wires things up, later instances are no-ops while one is active; state is shared
+ When set, the cors-proxy is only a fallback for the Trusted List fetch (always used for OCSP).

## Legal disclaimer
> CreeP7M performs technical signature verification and
> best-effort eIDAS qualification inference from certificate claims and the
> trusted list. It is **NOT a qualified validation service** and its results have **no legal value**. For legally binding
> validation rely on a Qualified Trust Service Provider or the official
> national/EU validators.

## Build OpenSSL to WebAssembly
A prebuilt binary is already provided but you can build your own.\
The GitHub Actions workflow `.github/workflows/build-openssl.yml` rebuilds it (emsdk 4.0.23, openssl-3.5 by default) and opens a PR with the result. Manual steps below.
### Download and prepare Emscripten environment
git clone https://github.com/emscripten-core/emsdk.git \
cd emsdk \
./emsdk install 4.0.23 \
./emsdk activate 4.0.23 \
source ./emsdk_env.sh \
export CC=emcc \
export CXX=emcc
### Build OpenSSL
git clone -b openssl-3.5 https://github.com/openssl/openssl.git \
cd openssl \
emconfigure ./Configure no-hw no-shared no-asm no-threads no-ssl3 no-dtls no-engine no-dso linux-x32 -static \
sed -i 's/$(CROSS_COMPILE)//' Makefile \
emmake make -j 16 build_generated libssl.a libcrypto.a apps/openssl CFLAGS="-O2 -s ENVIRONMENT='web' -s FILESYSTEM=1 -s MODULARIZE=1 -s EXPORTED_RUNTIME_METHODS=\"['callMain', 'FS', 'TTY']\" -s INVOKE_RUN=0 -s EXIT_RUNTIME=1 -s EXPORT_ES6=0 -s EXPORT_NAME='CreeP7M_openssl' -s ALLOW_MEMORY_GROWTH=1 -l proxyfs.js"

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
https://www.openssl.org/docs/man3.5/man1/openssl-cms.html \
https://www.agid.gov.it/it/piattaforme/firma-elettronica-qualificata/software-verifica \
https://github.com/esig/dss/blob/master/dss-cookbook/src/main/asciidoc/_chapters/eSignatures-and-dss.adoc#TrustedLists

## License & Copyright
[Copyright 2023-2026 lestoilfante](https://github.com/lestoilfante)

GNU General Public License version 3 (GPLv3)
