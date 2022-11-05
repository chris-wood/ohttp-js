import { KeyConfig, Client, Server } from "../src/ohttp";

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
        expect(responseContext.request).toStrictEqual(encodedRequest);

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
        expect(responseContext.request).toStrictEqual(encodedRequest);

        let serverResponse = await responseContext.encapsulate(encodedResponse);
        let encodedServerResponse = serverResponse.encode();

        let finalResponse = await requestContext.decodeAndDecapsulate(encodedServerResponse);
        expect(finalResponse).toStrictEqual(encodedResponse);
    });
});