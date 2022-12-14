import { loadCrypto } from "./webCrypto.ts";
import { concatArrays, i2Osp, max } from "./utils.ts";
import {
  InvalidConfigIdError,
  InvalidContentTypeError,
  InvalidHpkeCiphersuiteError,
} from "./errors.ts";

import { Aead, CipherSuite, Kdf, Kem } from "hpke";
import { BHttpDecoder, BHttpEncoder } from "bhttp";

const invalidKeyIdErrorString = "Invalid configuration ID";
const invalidHpkeCiphersuiteErrorString = "Invalid HPKE ciphersuite";
const invalidContentTypeErrorString = "Invalid content type";

const requestInfoLabel = "message/bhttp response";
const responseInfoLabel = "message/bhttp response";
const aeadKeyLabel = "key";
const aeadNonceLabel = "nonce";

async function randomBytes(l: number): Promise<Uint8Array> {
  const buffer = new Uint8Array(l);
  const cryptoApi = await loadCrypto();
  cryptoApi.getRandomValues(buffer);
  return buffer;
}

function checkHpkeCiphersuite(kem: Kem, kdf: Kdf, aead: Aead) {
  if (
    kem != Kem.DhkemX25519HkdfSha256 &&
    kdf != Kdf.HkdfSha256 &&
    aead != Aead.Aes128Gcm
  ) {
    throw new InvalidHpkeCiphersuiteError(invalidHpkeCiphersuiteErrorString);
  }
}

export class KeyConfig {
  public keyId: number;
  public kem: Kem;
  public kdf: Kdf;
  public aead: Aead;
  public keyPair: Promise<CryptoKeyPair>; // XXX(caw): should this be public?

  constructor(keyId: number) {
    if (keyId < 0 || keyId > 255) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    this.keyId = keyId;
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
    const publicKey = (await this.keyPair).publicKey;
    return new PublicKeyConfig(
      this.keyId,
      this.kem,
      this.kdf,
      this.aead,
      publicKey,
    );
  }
}

export class PublicKeyConfig {
  public keyId: number;
  public kem: Kem;
  public kdf: Kdf;
  public aead: Aead;
  public publicKey: CryptoKey; // XXX(caw): should this be public?

  constructor(
    keyId: number,
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
    publicKey: CryptoKey,
  ) {
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
    return concatArrays(this.responseNonce, this.encResponse);
  }
}

export class ServerResponseContext {
  public readonly encodedRequest: Uint8Array;
  private enc: Uint8Array;
  private secret: Uint8Array;
  private suite: CipherSuite;

  constructor(
    suite: CipherSuite,
    request: Uint8Array,
    secret: Uint8Array,
    enc: Uint8Array,
  ) {
    this.encodedRequest = request;
    this.enc = enc;
    this.secret = secret;
    this.suite = suite;
  }

  async encapsulate(encodedResponse: Uint8Array): Promise<ServerResponse> {
    const responseNonce = await randomBytes(
      max(this.suite.aeadKeySize, this.suite.aeadNonceSize),
    );
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
    const encResponse = new Uint8Array(
      await aeadKeyS.seal(
        aeadNonce,
        encodedResponse,
        new TextEncoder().encode(""),
      ),
    );

    return new ServerResponse(responseNonce, encResponse);
  }

  async encapsulateResponse(response: Response): Promise<Response> {
    const encoder = new BHttpEncoder();
    const encodedResponse = await encoder.encodeResponse(response);

    const serverResponse = await this.encapsulate(encodedResponse);
    return new Response(serverResponse.encode(), {
      status: 200,
      headers: {
        "Content-Type": "message/ohttp-res",
      },
    });
  }

  request(): Request {
    const decoder = new BHttpDecoder();
    return decoder.decodeRequest(this.encodedRequest);
  }
}

export class Server {
  private config: KeyConfig;
  private suite: CipherSuite;

  constructor(config: KeyConfig) {
    this.config = config;
    this.suite = new CipherSuite({
      kem: this.config.kem,
      kdf: this.config.kdf,
      aead: this.config.aead,
    });
  }

  async decapsulate(
    clientRequest: ClientRequest,
  ): Promise<ServerResponseContext> {
    // XXX(caw): move to header and create during construction (in prepare helper function)
    let hdr = new Uint8Array([this.config.keyId]);
    hdr = concatArrays(hdr, i2Osp(this.suite.kem, 2));
    hdr = concatArrays(hdr, i2Osp(this.suite.kdf, 2));
    hdr = concatArrays(hdr, i2Osp(this.suite.aead, 2));

    let info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
    info = concatArrays(info, new Uint8Array([0x00]));
    info = concatArrays(info, hdr);

    const recipientKeyPair = await this.config.keyPair;
    const recipient = await this.suite.createRecipientContext({
      recipientKey: recipientKeyPair,
      enc: clientRequest.enc,
      info: info,
    });

    const request = new Uint8Array(
      await recipient.open(clientRequest.encapsulatedReq),
    );

    const exportContext = new TextEncoder().encode(responseInfoLabel);
    const secret = new Uint8Array(
      await recipient.export(exportContext, this.suite.aeadKeySize),
    );

    return new ServerResponseContext(
      this.suite,
      request,
      secret,
      clientRequest.enc,
    );
  }

  async decodeAndDecapsulate(msg: Uint8Array): Promise<ServerResponseContext> {
    const encSize = this.suite.kemEncSize;
    const enc = msg.slice(0, encSize);
    const encRequest = msg.slice(encSize, msg.length);
    return await this.decapsulate(new ClientRequest(enc, encRequest));
  }

  async decapsulateRequest(request: Request): Promise<ServerResponseContext> {
    const { headers } = request;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-req") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    const encapRequestBody = new Uint8Array(await request.arrayBuffer());
    return this.decodeAndDecapsulate(encapRequestBody);
  }
}

export class Client {
  private config: PublicKeyConfig;
  private suite: CipherSuite;

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
    let hdr = new Uint8Array([this.config.keyId]);
    hdr = concatArrays(hdr, i2Osp(this.suite.kem, 2));
    hdr = concatArrays(hdr, i2Osp(this.suite.kdf, 2));
    hdr = concatArrays(hdr, i2Osp(this.suite.aead, 2));

    let info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
    info = concatArrays(info, new Uint8Array([0x00]));
    info = concatArrays(info, hdr);

    const publicKey = this.config.publicKey;
    const sender = await this.suite.createSenderContext({
      recipientPublicKey: publicKey,
      info: info,
    });

    const encRequest = new Uint8Array(await sender.seal(encodedRequest));
    const enc = new Uint8Array(sender.enc);
    const exportContext = new TextEncoder().encode(responseInfoLabel);
    const secret = new Uint8Array(
      await sender.export(exportContext, this.suite.aeadKeySize),
    );
    const clientRequest = new ClientRequestContext(
      this.suite,
      encRequest,
      enc,
      secret,
    );

    return clientRequest;
  }

  async encapsulateRequest(
    originalRequest: Request,
  ): Promise<ClientRequestContext> {
    const encoder = new BHttpEncoder();
    const encodedRequest = await encoder.encodeRequest(originalRequest);
    const encapRequestContext = await this.encapsulate(encodedRequest);
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
    const encapsulatedRequest = this.encode();
    return new Request(relayUrl, {
      method: "POST",
      body: encapsulatedRequest,
      headers: {
        "Content-Type": "message/ohttp-req",
      },
    });
  }
}

class ClientRequestContext {
  public readonly request: ClientRequest;
  private secret: Uint8Array;
  private suite: CipherSuite;

  constructor(
    suite: CipherSuite,
    encapsulatedReq: Uint8Array,
    enc: Uint8Array,
    secret: Uint8Array,
  ) {
    this.request = new ClientRequest(enc, encapsulatedReq);
    this.secret = secret;
    this.suite = suite;
  }

  async decapsulate(serverResponse: ServerResponse): Promise<Uint8Array> {
    const senderEnc = new Uint8Array(
      this.request.enc,
      0,
      this.request.enc.length,
    );
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
    const request = new Uint8Array(
      await aeadKeyS.open(
        aeadNonce,
        serverResponse.encResponse,
        new TextEncoder().encode(""),
      ),
    );

    return request;
  }

  async decodeAndDecapsulate(msg: Uint8Array): Promise<Uint8Array> {
    const responseNonceLen = max(
      this.suite.aeadKeySize,
      this.suite.aeadNonceSize,
    );
    const responseNonce = msg.slice(0, responseNonceLen);
    const encResponse = msg.slice(responseNonceLen, msg.length);
    return await this.decapsulate(
      new ServerResponse(responseNonce, encResponse),
    );
  }

  async decapsulateResponse(response: Response): Promise<Response> {
    const { headers } = response;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-res") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    const encapResponseBody = new Uint8Array(await response.arrayBuffer());
    const encodedResponse = await this.decodeAndDecapsulate(encapResponseBody);

    const decoder = new BHttpDecoder();
    return decoder.decodeResponse(encodedResponse);
  }
}
