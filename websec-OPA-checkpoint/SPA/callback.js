import { UserManager, settings } from "./settings";
import { log } from "./spa";

new UserManager(settings).signinRedirectCallback().then(function(user) {
    console.log("signin response success", user);
    log("login successful");
    window.location.href = './index.html?login=successful'; // Redirect with query parameter
}).catch(function(err) {
    log(err);
    console.log(err);
});
