import { loadCrypto } from "./webCrypto";
import { i2Osp, concatArrays, max } from "./utils";

const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function randomBytes(l:number): Promise<Uint8Array> {
    var buffer = new Uint8Array(l);
    let cryptoApi = await loadCrypto();
    cryptoApi.getRandomValues(buffer);
    return buffer;
}

export class KeyConfig {
    kem: typeof Kem;
    kdf: typeof Kdf;
    aead: typeof Aead;
    keyPair: Promise<CryptoKeyPair>;
 
    constructor() {
        this.kem = Kem.DhkemP256HkdfSha256;
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
            this.kem,
            this.kdf,
            this.aead,
            publicKey,
        )
    }
}

export class PublicKeyConfig {
    kem: typeof Kem;
    kdf: typeof Kdf;
    aead: typeof Aead;
    publicKey: CryptoKey;

    constructor(kem: typeof Kem, kdf: typeof Kdf, aead: typeof Aead, publicKey: CryptoKey) {
        // XXX(caw): check these for validity
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
}

export class ServerResponseContext {
    public readonly request: Uint8Array;

    enc: Uint8Array;
    secret: Uint8Array;
    suite: typeof CipherSuite;

    // XXX(caw): tidy up this interface
    constructor(request: Uint8Array, suite: typeof CipherSuite, secret: Uint8Array, enc: Uint8Array) {
        this.request = request;
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
            new TextEncoder().encode("key"),
            this.suite.aeadKeySize,
        );
        const aeadNonce = await kdf.expand(
            prk,
            new TextEncoder().encode("nonce"),
            this.suite.aeadNonceSize,
        );

        const aeadKeyS = await this.suite.createAeadKey(aeadKey);
        const encResponse = await aeadKeyS.seal(aeadNonce, encodedResponse, new TextEncoder().encode(""));

        return new ServerResponse(responseNonce, encResponse);
    }
}

export class Server {
    config: KeyConfig;
    suite: typeof CipherSuite;

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
        const key_id = 0x00;
        const kem_id = i2Osp(this.suite.kem, 2);
        const kdf_id = i2Osp(this.suite.kdf, 2);
        const aead_id = i2Osp(this.suite.aead, 2);
        var hdr = new Uint8Array([key_id]);
        hdr = concatArrays(hdr, kem_id);
        hdr = concatArrays(hdr, kdf_id);
        hdr = concatArrays(hdr, aead_id);

        var info = new Uint8Array(new TextEncoder().encode("message/bhttp request")) // TODO(caw): move to constant
        info = concatArrays(info, new Uint8Array([0x00]))
        info = concatArrays(info, hdr)

        const recipientKeyPair = await this.config.keyPair;
        const recipient = await this.suite.createRecipientContext({
            recipientKey: recipientKeyPair,
            enc: clientRequest.enc,
            info: info,
        });
          
        const request = new Uint8Array(await recipient.open(clientRequest.encapsulatedReq));
        
        const exportContext = new TextEncoder().encode("message/bhttp response"); // TODO(caw): move to constant
        const secret = new Uint8Array(recipient.export(exportContext, this.suite.aeadKeySize));

        return new ServerResponseContext(request, this.suite, secret, clientRequest.enc);
    }
}

export class Client {
    config: PublicKeyConfig;
    suite: typeof CipherSuite;

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
        const key_id = 0x00;
        const kem_id = i2Osp(this.suite.kem, 2);
        const kdf_id = i2Osp(this.suite.kdf, 2);
        const aead_id = i2Osp(this.suite.aead, 2);
        var hdr = new Uint8Array([key_id]);
        hdr = concatArrays(hdr, kem_id);
        hdr = concatArrays(hdr, kdf_id);
        hdr = concatArrays(hdr, aead_id);

        var info = new Uint8Array(new TextEncoder().encode("message/bhttp request")) // TODO(caw): move to constant
        info = concatArrays(info, new Uint8Array([0x00]))
        info = concatArrays(info, hdr)

        const publicKey = await this.config.publicKey;
        const sender = await this.suite.createSenderContext({
            recipientPublicKey: publicKey,
            info: info,
        });

        const encRequest = await sender.seal(encodedRequest);
        const exportContext = new TextEncoder().encode("message/bhttp response"); // TODO(caw): move to constant
        const secret = new Uint8Array(sender.export(exportContext, this.suite.aeadKeySize));
        let clientRequest = new ClientRequestContext(encRequest, sender.enc, this.suite, secret);

        return clientRequest;
    }
}

class ClientRequest {
    public readonly encapsulatedReq: Uint8Array;
    public readonly enc: Uint8Array;

    constructor(enc: Uint8Array, encapsulatedReq: Uint8Array) {
        this.encapsulatedReq = encapsulatedReq;
        this.enc = enc;
    }
}

class ClientRequestContext {
    public readonly request: ClientRequest;

    secret: Uint8Array;
    suite: typeof CipherSuite;

    constructor(encapsulatedReq: Uint8Array, enc: Uint8Array, suite: typeof CipherSuite, secret: Uint8Array) {
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
            new TextEncoder().encode("key"), // TODO(caw): move to constant
            this.suite.aeadKeySize,
        );
        const aeadNonce = await kdf.expand(
            prk,
            new TextEncoder().encode("nonce"), // TODO(caw): move to constant
            this.suite.aeadNonceSize,
        );

        const aeadKeyS = await this.suite.createAeadKey(aeadKey);
        const request = new Uint8Array(await aeadKeyS.open(aeadNonce, serverResponse.encResponse, new TextEncoder().encode("")));

        return request;
    }
}