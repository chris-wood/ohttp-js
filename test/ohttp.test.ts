import {
  assertEquals,
  assertNotEquals,
  assertStrictEquals,
} from "testing/asserts.ts";
import { describe, it } from "testing/bdd.ts";

import { loadCrypto } from "../src/webCrypto.ts";
import {
  Client,
  ClientConstructor,
  DeterministicKeyConfig,
  KeyConfig,
  Server,
} from "../src/ohttp.ts";

async function randomBytes(l: number): Promise<Uint8Array> {
  const buffer = new Uint8Array(l);
  const cryptoApi = await loadCrypto();
  cryptoApi.getRandomValues(buffer);
  return buffer;
}

function hexToArrayBuffer(input: String): Uint8Array {
  const view = new Uint8Array(input.length / 2)
  for (let i = 0; i < input.length; i += 2) {
    view[i / 2] = parseInt(input.substring(i, i + 2), 16)
  }
  return view;
}

function toHex(s: Uint8Array): String {
  return Array.from(s)
    .map((i) => i.toString(16).padStart(2, '0'))
    .join('');
}

describe("test OHTTP end-to-end", () => {
  it("Request label bug", async () => {
    const keyId = 0x01;
    const seed = new Uint8Array([
      0x45, 0x04, 0xe2, 0x24, 0x51, 0xe6, 0x53, 0x5c, 0xac, 0x1e, 0x89, 0x4e,
      0x35, 0xb0, 0x75, 0x41, 0xc0, 0x0f, 0x8a, 0xa2, 0x45, 0xb8, 0x36, 0x0c,
      0x06, 0x43, 0x3c, 0x46, 0x85, 0x9a, 0x79, 0xd7
    ]);
    const keyConfig = new DeterministicKeyConfig(keyId, seed);
    const server = new Server(keyConfig);

    const encodedClientRequestStr = "010020000100016f026e20fa4024c3852641f91177cf188c70b341d20e4f51ee8e8f1b6ad9a8566bd28fa76ce7869a0db0555f251db8411c32f4686661db5141d76e6dcc538c30a6e6cb6d0b1554ec9d5a6256b2fec49b47ebec510e70d12f249744d638a3275168e56e4c4cebd56288091ae448a1d42f6573611b32242907dfa3ed589e4537821d";
    const encodedClientRequest = hexToArrayBuffer(encodedClientRequestStr);

    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    const receivedRequest = responseContext.request();
    assertEquals(receivedRequest.url, "https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html");

  });

  it("Happy Path", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicKeyConfig = await keyConfig.publicConfig();

    const encodedRequest = new TextEncoder().encode("Happy");
    const encodedResponse = new TextEncoder().encode("Path");

    const client = new Client(publicKeyConfig);
    const requestContext = await client.encapsulate(encodedRequest);
    const clientRequest = requestContext.request;

    const server = new Server(keyConfig);
    const responseContext = await server.decapsulate(clientRequest);
    assertEquals(responseContext.encodedRequest, encodedRequest);

    const serverResponse = await responseContext.encapsulate(encodedResponse);
    const finalResponse = await requestContext.decapsulate(serverResponse);
    assertEquals(finalResponse, encodedResponse);
  });

  it("Happy Path with encoding and decoding", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const server = new Server(keyConfig);

    const encodedKeyConfig = await server.encodeKeyConfig();

    const encodedRequest = new TextEncoder().encode("Happy");
    const encodedResponse = new TextEncoder().encode("Path");

    const constructor = new ClientConstructor();
    const client = await constructor.clientForConfig(encodedKeyConfig);
    const requestContext = await client.encapsulate(encodedRequest);
    const clientRequest = requestContext.request;
    const encodedClientRequest = clientRequest.encode();

    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    assertEquals(responseContext.encodedRequest, encodedRequest);

    const serverResponse = await responseContext.encapsulate(encodedResponse);
    const encodedServerResponse = serverResponse.encode();

    const finalResponse = await requestContext.decodeAndDecapsulate(
      encodedServerResponse,
    );
    assertEquals(finalResponse, encodedResponse);
  });

  it("Happy Path with Request/Response encoding and decoding", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicKeyConfig = await keyConfig.publicConfig();

    const requestUrl = "https://target.example/query?foo=bar";
    const request = new Request(requestUrl);
    const response = new Response("baz", {
      headers: { "Content-Type": "text/plain" },
    });

    const client = new Client(publicKeyConfig);
    const requestContext = await client.encapsulateRequest(request);
    const clientRequest = requestContext.request;
    const encodedClientRequest = clientRequest.encode();

    const server = new Server(keyConfig);
    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    const receivedRequest = responseContext.request();
    assertStrictEquals(receivedRequest.url, "https://target.example/query");

    const serverResponse = await responseContext.encapsulateResponse(response);

    const finalResponse = await requestContext.decapsulateResponse(
      serverResponse,
    );
    assertStrictEquals(finalResponse.headers.get("Content-Type"), "text/plain");
    const body = await finalResponse.arrayBuffer();
    assertStrictEquals(new TextDecoder().decode(new Uint8Array(body)), "baz");
  });

  it("Happy Path with a deterministic KeyConfig", async () => {
    const keyId = 0x01;
    const seed = await randomBytes(32);

    // Create a pair of servers with the same config and make sure they result in the same public key configuration
    const keyConfig = new DeterministicKeyConfig(keyId, seed);
    const server = new Server(keyConfig);
    const sameConfig = new DeterministicKeyConfig(keyId, seed);
    const sameServer = new Server(sameConfig);
    const diffConfig = new KeyConfig(keyId);
    const diffServer = new Server(diffConfig);

    const configA = await server.encodeKeyConfig();
    const configB = await sameServer.encodeKeyConfig();
    const configC = await diffServer.encodeKeyConfig();
    assertEquals(configA, configB);
    assertNotEquals(configA, configC);

    const publicKeyConfig = await keyConfig.publicConfig();

    const requestUrl = "https://target.example/query?foo=bar";
    const request = new Request(requestUrl);
    const response = new Response("baz", {
      headers: { "Content-Type": "text/plain" },
    });

    const client = new Client(publicKeyConfig);
    const requestContext = await client.encapsulateRequest(request);
    const clientRequest = requestContext.request;
    const encodedClientRequest = clientRequest.encode();

    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    const receivedRequest = responseContext.request();
    assertStrictEquals(receivedRequest.url, "https://target.example/query");

    const serverResponse = await responseContext.encapsulateResponse(response);

    const finalResponse = await requestContext.decapsulateResponse(
      serverResponse,
    );
    assertStrictEquals(finalResponse.headers.get("Content-Type"), "text/plain");
    const body = await finalResponse.arrayBuffer();
    assertStrictEquals(new TextDecoder().decode(new Uint8Array(body)), "baz");
  });

  it("KeyConfig encoding and decoding", async () => {
    const keyId = 0x01;
    const seed = await randomBytes(32);

    // Create a pair of servers with the same config and make sure they result in the same public key configuration
    const keyConfig = new DeterministicKeyConfig(keyId, seed);
    const publicConfig = await keyConfig.publicConfig();
    const encodedConfig = await publicConfig.encode();

    // Ensure the preamble matches
    assertEquals(encodedConfig.slice(0, 3), new Uint8Array([0x01, 0x00, 0x20]));

    // Ensure the public key matches
    const kemContext = await publicConfig.suite.kemContext();
    const encodedKey = new Uint8Array(
      await kemContext.serializePublicKey(
        publicConfig.publicKey,
      ),
    );
    assertEquals(encodedConfig.slice(3, 3 + encodedKey.length), encodedKey);

    // Ensure the tail matches
    assertEquals(
      encodedConfig.slice(3 + encodedKey.length, 3 + encodedKey.length + 6),
      new Uint8Array([0x00, 0x04, 0x00, 0x01, 0x00, 0x01]),
    );
  });
});
