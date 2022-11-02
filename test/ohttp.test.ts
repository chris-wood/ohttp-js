import { max, KeyConfig, Client, Server } from "../src/ohttp";

describe("test max function", () => {
    it("max(1,0) = 1", () => {
        expect(max(1, 0)).toBe(1);
    });

    it("max(0,1) = 1", () => {
        expect(max(0, 1)).toBe(1);
    });
});

describe("test OHTTP end-to-end", () => {
    it("Happy Path", async () => {
        const keyConfig = new KeyConfig();
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
});