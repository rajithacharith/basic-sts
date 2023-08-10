import ballerina/log;
import ballerina/regex;
import ballerina/lang.array;
import bal_basic_sts.applications;
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

    resource function post token(@http:Header{name:http:AUTHORIZATION} string authorization) returns TokenResponse|http:BadRequest|error {
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
            return {
                access_token: "",
                token_type: "",
                expires_in: ""
            };
        }
        return <http:BadRequest>{body: "Invalid client credentials"}; 
    }
}
