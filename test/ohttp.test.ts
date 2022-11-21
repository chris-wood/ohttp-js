import { enableFetchMocks } from "jest-fetch-mock";
import { KeyConfig, Client, Server } from "../src/ohttp";

enableFetchMocks();

describe("test OHTTP end-to-end", () => {
    it("Happy Path", async () => {
        const keyId = 0x01;
        const keyConfig = new KeyConfig(keyId);
        const publicKeyConfig = await keyConfig.publicConfig();

        let encodedRequest = new TextEncoder().encode("Happy");
        let encodedResponse = new TextEncoder().encode("Path");

        let client = new Client(publicKeyConfig);
        let requestContext = await client.encapsulate(encodedRequest);
        let clientRequest = requestContext.request;

        let server = new Server(keyConfig);
        let responseContext = await server.decapsulate(clientRequest);
        expect(responseContext.encodedRequest).toStrictEqual(encodedRequest);

        let serverResponse = await responseContext.encapsulate(encodedResponse);
        let finalResponse = await requestContext.decapsulate(serverResponse);
        expect(finalResponse).toStrictEqual(encodedResponse);
    });

    it("Happy Path with encoding and decoding", async () => {
        const keyId = 0x01;
        const keyConfig = new KeyConfig(keyId);
        const publicKeyConfig = await keyConfig.publicConfig();

        let encodedRequest = new TextEncoder().encode("Happy");
        let encodedResponse = new TextEncoder().encode("Path");

        let client = new Client(publicKeyConfig);
        let requestContext = await client.encapsulate(encodedRequest);
        let clientRequest = requestContext.request;
        let encodedClientRequest = clientRequest.encode();

        let server = new Server(keyConfig);
        let responseContext = await server.decodeAndDecapsulate(encodedClientRequest);
        expect(responseContext.encodedRequest).toStrictEqual(encodedRequest);

        let serverResponse = await responseContext.encapsulate(encodedResponse);
        let encodedServerResponse = serverResponse.encode();

        let finalResponse = await requestContext.decodeAndDecapsulate(encodedServerResponse);
        expect(finalResponse).toStrictEqual(encodedResponse);
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

        let client = new Client(publicKeyConfig);
        let requestContext = await client.encapsulateRequest(request);
        let clientRequest = requestContext.request;
        let encodedClientRequest = clientRequest.encode();

        let server = new Server(keyConfig);
        let responseContext = await server.decodeAndDecapsulate(encodedClientRequest);
        let receivedRequest = responseContext.request();
        expect(receivedRequest.url).toEqual("https://target.example/query");

        let serverResponse = await responseContext.encapsulateResponse(response);

        let finalResponse = await requestContext.decapsulateResponse(serverResponse);
        expect(finalResponse.headers.get("Content-Type")).toStrictEqual("text/plain");
        const body = await finalResponse.arrayBuffer();
        expect(new TextDecoder().decode(new Uint8Array(body))).toEqual("baz");
    });
});