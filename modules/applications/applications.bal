import ballerina/log;

public type Application record {
    string clientId;
    string clientSecret;
};

isolated Application[] applicationList = [];

function init() {
    _ = addApplication("admin", "admin");
    log:printInfo("Application list initialized");
}

public isolated function validateApplication(string clientId, string clientSecret) returns boolean {
    lock {
        foreach var application in applicationList {
            if (application.clientId == clientId && application.clientSecret == clientSecret) {
                return true;
            }
        }
        return false;
    }
}

public function addApplication(string clientId, string clientSecret) returns boolean {
    if (validateApplication(clientId, clientSecret)) {
        return false;
    }
    lock {
        applicationList.push({clientId: clientId, clientSecret: clientSecret});
    }
    return true;
}
