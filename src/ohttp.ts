import { loadCrypto } from "./webCrypto";
import { i2Osp, concatArrays, max } from "./utils";
import { InvalidConfigIdError, InvalidHpkeCiphersuiteError, InvalidContentTypeError } from "./errors";

const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");
const { BHttpEncoder, BHttpDecoder } = require("bhttp-js");

const invalidKeyIdErrorString = "Invalid configuration ID";
const invalidHpkeCiphersuiteErrorString = "Invalid HPKE ciphersuite";
const invalidContentTypeErrorString = "Invalid content type";

const requestInfoLabel = "message/bhttp response";
const responseInfoLabel = "message/bhttp response";
const aeadKeyLabel = "key";
const aeadNonceLabel = "nonce";

async function randomBytes(l:number): Promise<Uint8Array> {
    var buffer = new Uint8Array(l);
    let cryptoApi = await loadCrypto();
    cryptoApi.getRandomValues(buffer);
    return buffer;
}

function checkHpkeCiphersuite(kem: typeof Kem, kdf: typeof Kdf, aead: typeof Aead) {
    if (kem != Kem.DhkemX25519HkdfSha256 && 
        kdf != Kdf.HkdfSha256 &&
        aead != Aead.Aes128Gcm) {
        throw new InvalidHpkeCiphersuiteError(invalidHpkeCiphersuiteErrorString);
    }
}

export class KeyConfig {
    public keyId: number;
    public kem: typeof Kem;
    public kdf: typeof Kdf;
    public aead: typeof Aead;
    public keyPair: Promise<CryptoKeyPair>; // XXX(caw): should this be public?
 
    constructor(keyId: number) {
        if (keyId < 0 || keyId > 255) {
            throw new InvalidConfigIdError(invalidKeyIdErrorString);
        }
        this.keyId = keyId
        this.kem = Kem.DhkemX25519HkdfSha256;
        this.kdf = Kdf.HkdfSha256;
        this.aead = Aead.Aes128Gcm;
        const suite = new CipherSuite({
            kem: this.kem,
            kdf: this.kdf,
            aead: this.aead,
        });
        this.keyPair = suite.generateKeyPair();
    }

    async publicConfig(): Promise<PublicKeyConfig> {
        const publicKey = (await this.keyPair).publicKey
        return new PublicKeyConfig(
            this.keyId,
            this.kem,
            this.kdf,
            this.aead,
            publicKey,
        )
    }
}

export class PublicKeyConfig {
    public keyId: number;
    public kem: typeof Kem;
    public kdf: typeof Kdf;
    public aead: typeof Aead;
    public publicKey: CryptoKey; // XXX(caw): should this be public?

    constructor(keyId: number, kem: typeof Kem, kdf: typeof Kdf, aead: typeof Aead, publicKey: CryptoKey) {
        if (keyId < 0 || keyId > 255) {
            throw new InvalidConfigIdError(invalidKeyIdErrorString);
        }
        this.keyId = keyId;

        checkHpkeCiphersuite(kem, kdf, aead);
        this.kem = kem;
        this.kdf = kdf;
        this.aead = aead;
        this.publicKey = publicKey;
    }
}

export class ServerResponse {
    public readonly responseNonce: Uint8Array;
    public readonly encResponse: Uint8Array;

    constructor(responseNonce: Uint8Array, encResponse: Uint8Array) {
        this.responseNonce = responseNonce;
        this.encResponse = encResponse;
    }

    encode(): Uint8Array {
        return concatArrays(this.responseNonce, this.encResponse)
    }
}

export class ServerResponseContext {
    public readonly encodedRequest: Uint8Array;
    private enc: Uint8Array;
    private secret: Uint8Array;
    private suite: typeof CipherSuite;

    constructor(suite: typeof CipherSuite, request: Uint8Array, secret: Uint8Array, enc: Uint8Array) {
        this.encodedRequest = request;
        this.enc = enc;
        this.secret = secret;
        this.suite = suite;
    }

    async encapsulate(encodedResponse: Uint8Array): Promise<ServerResponse> {
        const responseNonce = await randomBytes(max(this.suite.aeadKeySize, this.suite.aeadNonceSize));
        const salt = concatArrays(new Uint8Array(this.enc), responseNonce);

        const kdf = await this.suite.kdfContext();
        const prk = await kdf.extract(salt, this.secret);
        const aeadKey = await kdf.expand(
            prk,
            new TextEncoder().encode(aeadKeyLabel),
            this.suite.aeadKeySize,
        );
        const aeadNonce = await kdf.expand(
            prk,
            new TextEncoder().encode(aeadNonceLabel),
            this.suite.aeadNonceSize,
        );

        const aeadKeyS = await this.suite.createAeadKey(aeadKey);
        const encResponse = new Uint8Array(await aeadKeyS.seal(aeadNonce, encodedResponse, new TextEncoder().encode("")));

        return new ServerResponse(responseNonce, encResponse);
    }

    async encapsulateResponse(response: Response): Promise<Response> {
        let encoder = new BHttpEncoder();
        let encodedResponse = await encoder.encodeResponse(response);

        let serverResponse = await this.encapsulate(encodedResponse);
        return new Response(serverResponse.encode(), {
            status: 200,
            headers: {
                'Content-Type': "message/ohttp-res",
            }
        });
    }

    request(): Request {
        let decoder = new BHttpDecoder();
        return decoder.decodeRequest(this.encodedRequest);
    }
}

export class Server {
    private config: KeyConfig;
    private suite: typeof CipherSuite;

    constructor(config: KeyConfig) {
        this.config = config;
        this.suite = new CipherSuite({
            kem: this.config.kem,
            kdf: this.config.kdf,
            aead: this.config.aead,
        });
    }

    async decapsulate(clientRequest: ClientRequest): Promise<ServerResponseContext> {
        // XXX(caw): move to header and create during construction (in prepare helper function)
        var hdr = new Uint8Array([this.config.keyId]);
        hdr = concatArrays(hdr, i2Osp(this.suite.kem, 2));
        hdr = concatArrays(hdr, i2Osp(this.suite.kdf, 2));
        hdr = concatArrays(hdr, i2Osp(this.suite.aead, 2));

        var info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
        info = concatArrays(info, new Uint8Array([0x00]));
        info = concatArrays(info, hdr);

        const recipientKeyPair = await this.config.keyPair;
        const recipient = await this.suite.createRecipientContext({
            recipientKey: recipientKeyPair,
            enc: clientRequest.enc,
            info: info,
        });
          
        const request = new Uint8Array(await recipient.open(clientRequest.encapsulatedReq));
        
        const exportContext = new TextEncoder().encode(responseInfoLabel);
        const secret = new Uint8Array(recipient.export(exportContext, this.suite.aeadKeySize));

        return new ServerResponseContext(this.suite, request, secret, clientRequest.enc);
    }

    async decodeAndDecapsulate(msg: Uint8Array): Promise<ServerResponseContext> {
        let encSize = this.suite.kemEncSize;
        let enc = msg.slice(0, encSize);
        let encRequest = msg.slice(encSize, msg.length);
        return this.decapsulate(new ClientRequest(enc, encRequest));
    }

    async decapsulateRequest(request: Request): Promise<ServerResponseContext> {
        const { headers } = request;
        const contentType = headers.get('content-type');
        if (contentType != "message/ohttp-req") {
            throw new InvalidContentTypeError(invalidContentTypeErrorString);
        }
    
        let encapRequestBody = new Uint8Array(await request.arrayBuffer());
        return this.decodeAndDecapsulate(encapRequestBody);
    }
}

export class Client {
    private config: PublicKeyConfig;
    private suite: typeof CipherSuite;

    constructor(config: PublicKeyConfig) {
        this.config = config;
        this.suite = new CipherSuite({
            kem: this.config.kem,
            kdf: this.config.kdf,
            aead: this.config.aead,
        });
    }
   
    async encapsulate(encodedRequest: Uint8Array): Promise<ClientRequestContext> {
        // XXX(caw): move to header and create during construction (in prepare helper function)
        var hdr = new Uint8Array([this.config.keyId]);
        hdr = concatArrays(hdr, i2Osp(this.suite.kem, 2));
        hdr = concatArrays(hdr, i2Osp(this.suite.kdf, 2));
        hdr = concatArrays(hdr, i2Osp(this.suite.aead, 2));

        var info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
        info = concatArrays(info, new Uint8Array([0x00]));
        info = concatArrays(info, hdr);

        const publicKey = await this.config.publicKey;
        const sender = await this.suite.createSenderContext({
            recipientPublicKey: publicKey,
            info: info,
        });

        const encRequest = new Uint8Array(await sender.seal(encodedRequest));
        const enc = new Uint8Array(sender.enc);
        const exportContext = new TextEncoder().encode(responseInfoLabel);
        const secret = new Uint8Array(sender.export(exportContext, this.suite.aeadKeySize));
        let clientRequest = new ClientRequestContext(this.suite, encRequest, enc, secret);

        return clientRequest;
    }

    async encapsulateRequest(originalRequest: Request): Promise<ClientRequestContext> {
        let encoder = new BHttpEncoder();
        let encodedRequest = await encoder.encodeRequest(originalRequest);
        let encapRequestContext = await this.encapsulate(encodedRequest);
        return encapRequestContext;
    }
}

class ClientRequest {
    public readonly encapsulatedReq: Uint8Array;
    public readonly enc: Uint8Array;

    constructor(enc: Uint8Array, encapsulatedReq: Uint8Array) {
        this.encapsulatedReq = encapsulatedReq;
        this.enc = enc;
    }

    encode(): Uint8Array {
        const result = concatArrays(this.enc, this.encapsulatedReq);
        return result;
    }

    request(relayUrl: string): Request {
        let encapsulatedRequest = this.encode();
        return new Request(relayUrl, {
            method: 'POST', 
            body: encapsulatedRequest,
            headers: {
                'Content-Type': 'message/ohttp-req'
            },
        });
    }
}

class ClientRequestContext {
    public readonly request: ClientRequest;
    private secret: Uint8Array;
    private suite: typeof CipherSuite;

    constructor(suite: typeof CipherSuite, encapsulatedReq: Uint8Array, enc: Uint8Array, secret: Uint8Array) {
        this.request = new ClientRequest(enc, encapsulatedReq);
        this.secret = secret;
        this.suite = suite;
    }
   
    async decapsulate(serverResponse: ServerResponse): Promise<Uint8Array> {
        const senderEnc = new Uint8Array(this.request.enc, 0, this.request.enc.length);
        const salt = concatArrays(senderEnc, serverResponse.responseNonce);

        const kdf = await this.suite.kdfContext();
        const prk = await kdf.extract(salt, this.secret);
        const aeadKey = await kdf.expand(
            prk,
            new TextEncoder().encode(aeadKeyLabel),
            this.suite.aeadKeySize,
        );
        const aeadNonce = await kdf.expand(
            prk,
            new TextEncoder().encode(aeadNonceLabel),
            this.suite.aeadNonceSize,
        );

        const aeadKeyS = await this.suite.createAeadKey(aeadKey);
        const request = new Uint8Array(await aeadKeyS.open(aeadNonce, serverResponse.encResponse, new TextEncoder().encode("")));

        return request;
    }

    async decodeAndDecapsulate(msg: Uint8Array): Promise<Uint8Array> {
        let responseNonceLen = max(this.suite.aeadKeySize, this.suite.aeadNonceSize)
        let responseNonce = msg.slice(0, responseNonceLen);
        let encResponse = msg.slice(responseNonceLen, msg.length);
        return this.decapsulate(new ServerResponse(responseNonce, encResponse));
    }

    async decapsulateResponse(response: Response): Promise<Request> {
        const { headers } = response;
        const contentType = headers.get('content-type');
        if (contentType != "message/ohttp-res") {
            throw new InvalidContentTypeError(invalidContentTypeErrorString);
        }
    
        let encapResponseBody = new Uint8Array(await response.arrayBuffer());
        let encodedRequest = await this.decodeAndDecapsulate(encapResponseBody);

        let decoder = new BHttpDecoder();
        return decoder.decodeResponse(encodedRequest);
    }
}