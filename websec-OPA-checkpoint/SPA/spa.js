
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import { UserManager, settings } from "./settings";

///////////////////////////////
// UI event handlers
///////////////////////////////
const maxLogEntries = 2; // Set default maximum number of log entries

document.getElementById("clearState").addEventListener("click", clearState, false);
document.getElementById("getUser").addEventListener("click", getUser, false);
document.getElementById("orderFristi").addEventListener("click", orderFristi, false);
document.getElementById("orderBeer").addEventListener("click", orderBeer, false);
document.getElementById("manageDrinks").addEventListener("click", manageDrinks, false);
document.getElementById('clearLogs').addEventListener('click', function() {
    document.getElementById('out').innerHTML = ''; // Clears the content of the log
});
document.getElementById('clearAllLogs').addEventListener('click', function() {
    document.getElementById('out').innerHTML = ''; // Clears the content of the SPA log
    document.getElementById('result').innerText= '';
});
document.getElementById("toggleLogs").addEventListener("click", function() {
    var container = document.querySelector('.block-logs-container');
    if (container.style.display === "none") {
        container.style.display = "";
    } else {
        container.style.display = "none";
    }
});


document.getElementById("startSigninMainWindow").addEventListener("click", startSigninMainWindow, false);

document.getElementById("logoutUser").addEventListener("click", startSignoutMainWindow, false);

// Function to extract query parameters
function getQueryParams() {
    const params = {};
    window.location.search.substring(1).split("&").forEach(function(part) {
        const item = part.split("=");
        params[item[0]] = decodeURIComponent(item[1]);
    });
    return params;
}

// Main logic for the index page
document.addEventListener("DOMContentLoaded", () => {
    const userManager = new UserManager(settings);
    const queryParams = getQueryParams();

    // Check if we were redirected here after a successful login
    if (queryParams.login === 'successful') {
        log('Login successful');
        userManager.getUser().then(user => {
            if (user) {
                // Perform actions with the user object as needed
                log(`User logged in: ${user.profile.email}`);
            } else {
                log('No user logged in');
            }
        }).catch(err => {
            log(err);
        });
    }
});
///////////////////////////////
// config
///////////////////////////////

function sendRequest(url, token, data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", url);

    // Headers you're setting for the request
    const requestHeaders = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
    };

    // Set headers on the XMLHttpRequest object
    Object.keys(requestHeaders).forEach(key => {
        xhr.setRequestHeader(key, requestHeaders[key]);
    });

    // Log the request details including headers
    logRequest(url, data, requestHeaders);

    xhr.onload = function () {
        let response;
        try {
            response = JSON.parse(xhr.responseText);
        } catch (error) {
            response = xhr.responseText;
        }
        // Log the response details
        callback(true, 'response', {type: 'response', content: `Response Status: ${xhr.status}\nResponse Data: ${JSON.stringify(response, null, 2)}`});
    };

    xhr.send(JSON.stringify(data));
}

function logRequest(url, requestData, requestHeaders) {
    // Format the request log to include headers
    var requestLog = `Request URL: ${url}\nRequest Headers: ${JSON.stringify(requestHeaders, null, 2)}\nRequest Data: ${JSON.stringify(requestData, null, 2)}`;
    log(true, 'request', {type: 'request', content: requestLog}); // Passing special parameters for HTTP logging
}


function orderFristi() {
    mgr.getUser().then(function (user) {
        sendRequest(settings.api_bar_uri, user.access_token, { DrinkName: "Fristi" }, log);
    });
}

function orderBeer() {
    mgr.getUser().then(function (user) {
        sendRequest(settings.api_bar_uri, user.access_token, { DrinkName: "Beer" }, log);
    });
}

function manageDrinks() {
    mgr.getUser().then(function (user) {
        sendRequest(settings.api_manageBar_uri, user.access_token, { DrinkName: "Whiskey" }, log);
    });
}

function log() {
    var logContainer = document.getElementById("out");
    var isSpecialLog = arguments.length > 1 && typeof arguments[0] === 'boolean' && typeof arguments[1] === 'string';
    var startIndex = isSpecialLog ? 2 : 0;

    var logEntry = document.createElement("div");
    logEntry.className = "http-log";

    Array.prototype.slice.call(arguments, startIndex).forEach(function(msg) {
        var messageElement = document.createElement("div");
        if (typeof msg === "object" && msg !== null && (msg.type === 'request' || msg.type === 'response')) {
            messageElement.textContent = msg.content + "\r\n";
            messageElement.className = `log-${msg.type}`;
        } else {
            if (msg instanceof Error) {
                msg = "Error: " + msg.message;
            } else if (typeof msg !== "string") {
                msg = JSON.stringify(msg, null, 2);
            }
            messageElement.textContent = msg + "\r\n";
        }
        logEntry.appendChild(messageElement);
        if (msg.type === 'response') {
            if(msg.content.includes("200"))
            {
                document.getElementById("result").textContent="GRANTED";
            }
            else if(msg.content.includes("403"))
            {
                document.getElementById("result").textContent="DENIED";
            }
            else
            {
                document.getElementById("result").textContent="";
            }
        }
    });

    let separator = document.createElement("div");
    separator.className = "http-transaction-separator";
    logEntry.insertBefore(separator, logEntry.firstChild);

    if (logContainer.children.length >= maxLogEntries) {
        logContainer.removeChild(logContainer.lastChild); // Remove the oldest log entry
    }

    logContainer.insertBefore(logEntry, logContainer.firstChild); // Insert the new log at the top
}




const mgr = new UserManager(settings);

///////////////////////////////
// events
///////////////////////////////
mgr.events.addAccessTokenExpiring(function () {
    console.log("token expiring");
    log("token expiring");
});

mgr.events.addAccessTokenExpired(function () {
    console.log("token expired");
    log("token expired");
});

mgr.events.addSilentRenewError(function (e) {
    console.log("silent renew error", e.message);
    log("silent renew error", e.message);
});

mgr.events.addUserLoaded(function (user) {
    console.log("user loaded", user);
    mgr.getUser().then(function() {
        console.log("getUser loaded user after userLoaded event fired");
    }, () => {});
});

mgr.events.addUserUnloaded(function (e) {
    console.log("user unloaded");
});

///////////////////////////////
// functions for UI elements
///////////////////////////////
function clearState() {
    mgr.clearStaleState().then(function() {
        log("Stated cleared");
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function getUser() {
    mgr.getUser().then(function(user) {
        log("Got user", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function startSigninMainWindow() {
    mgr.signinRedirect({ state: { some: "data" } }).then(function() {
        log("Signinredirect done");
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function endSigninMainWindow() {
    mgr.signinRedirectCallback().then(function(user) {
        log("Signed in", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function popupSignin() {
    mgr.signinPopup().then(function(user) {
        log("Signed in", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function popupSignout() {
    mgr.signoutPopup().then(function() {
        log("signed out");
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function iframeSignin() {
    mgr.signinSilent().then(function(user) {
        log("Signed in", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function startSignoutMainWindow() {
    mgr.signoutRedirect().then(function(resp) {
        log("Signed out", resp);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

function endSignoutMainWindow() {
    mgr.signoutRedirectCallback().then(function(resp) {
        log("Signed out", resp);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

export {
    log
};