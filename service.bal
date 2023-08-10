import ballerina/log;
import ballerina/regex;
import ballerina/lang.array;
import bal_basic_sts.applications;
import ballerina/jwt;
import ballerina/http;


type TokenResponse record {|
    string access_token;
    string token_type;
    string expires_in;
|};

@http:ServiceConfig {
    cors: {
        allowOrigins: ["*"],
        allowMethods: [http:GET, http:POST, http:PATCH, http:DELETE],
        allowHeaders: [http:AUTH_HEADER, http:CONTENT_TYPE],
        allowCredentials: false,
        maxAge: 84900
    }
}
service /oauth2 on new http:Listener(9090) {

    resource function post token(@http:Header{name:http:AUTHORIZATION} string authorization, @http:Payload string payload) returns TokenResponse|http:BadRequest|error {
        if payload is string {
            string[] params = regex:split(payload, "&");
            string grantType = "";
            string scopes = "";
            string username = "";
            string password = "";
            string refreshToken = "";
            foreach string param in params {
                if param.includes("grant_type=") {
                    grantType = regex:split(param, "=")[1];
                } else if param.includes("scope=") {
                    scopes = regex:split(param, "=")[1];
                } else if param.includes("username=") {
                    username = regex:split(param, "=")[1];
                } else if param.includes("password=") {
                    password = regex:split(param, "=")[1];
                } else if param.includes("refresh_token=") {
                    refreshToken = regex:split(param, "=")[1];
                    // If the refresh token contains the `=` symbol, then it is required to concatenate all the
                    // parts of the value since the `split` function breaks all those into separate parts.
                    if param.endsWith("==") {
                        refreshToken += "==";
                    }
                }
            }
            log:printInfo("Grant type: " + grantType);
        }
        

        log:printInfo("Authorization header: " + authorization);
        string[] headerArray = regex:split(authorization, " ");
        string authType = headerArray[0];
        string encodedString = headerArray[1];
        if (authType != "Basic") {
            return <http:BadRequest>{body: "Invalid authorization type"};
        }
        log:printInfo("Encoded string: " + encodedString);
        byte[] fromBase64 = check array:fromBase64(encodedString);
        string decodedString = check string:fromBytes(fromBase64);
        log:printInfo("Decoded string: " + decodedString);
        string[] decodedArray = regex:split(decodedString, ":");
        string clientId = decodedArray[0];
        string clientSecret = decodedArray[1];

        if applications:validateApplication(clientId, clientSecret) {
            jwt:IssuerConfig issuerConfig = {
                // The "iss" (issuer) claim identifies the principal that issued the JWT.
                issuer: "http://localhost:9090/oauth2/token",
                keyId: "dddd",
                audience: [clientId],
                customClaims: {
                    // Should be application UUID, but for the sake of simplicity, we are using client ID.
                    "sub": clientId,
                    // The "jti" (JWT ID) claim provides a unique identifier for the JWT.
                    "jti": "sdfsdf",
                    "client_id": clientId
                },
                expTime: 3600,
                signatureConfig: {
                    config: {
                        keyFile: "test_key.pem"
                    }
                }
            };
            // Ideally Access Token type should be "at+jwt", but ballerina jwt library does not support changing the type.
            string token = check jwt:issue(issuerConfig);
            return {
                access_token: token,
                token_type: "",
                expires_in: ""
            };
        }
        return <http:BadRequest>{body: "Invalid client credentials"}; 
    }
}
