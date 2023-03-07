import { assertEquals, assertStrictEquals } from "testing/asserts.ts";
import { describe, it } from "testing/bdd.ts";

import { Client, ClientConstructor, KeyConfig, Server } from "../src/ohttp.ts";

describe("test OHTTP end-to-end", () => {
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
});
