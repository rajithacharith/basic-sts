import ballerina/log;

public type Application record {
    string clientId;
    string clientSecret;
};

Application[] applicationList = [];

function init() {
    _ = addApplication("admin", "admin");
    log:printInfo("Application list initialized");
}

public function validateApplication(string clientId, string clientSecret) returns boolean {
    foreach var application in applicationList {
        if (application.clientId == clientId && application.clientSecret == clientSecret) {
            return true;
        }
    }
    return false;
}

public function addApplication(string clientId, string clientSecret) returns boolean {
    if (validateApplication(clientId, clientSecret)) {
        return false;
    }
    applicationList.push({clientId: clientId, clientSecret: clientSecret});
    return true;
}
