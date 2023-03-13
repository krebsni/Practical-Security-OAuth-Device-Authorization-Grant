var clientID = null;
var STARTDATE;
var TIMEOUT = 20;

// initiate device grant
function deviceGrant(url) {
    grantUrl = url + 'grant'
    ajaxPostJson(grantUrl, function(data) {
        console.log(data);
        if (data['error_message']){
            // error, most likely 503 during client registration in DOS scenario
            var html = "<br><p>" + data['error_message'] + "</p>";
            html += '<button onclick=deviceGrant(' + url + ')>Try again</button>';
            document.getElementById('display').innerHTML = html;
        } else {
            // display relevant data to user
            clientID = data['client_id'];

            var html = "<h2>Device Registration</h2>";
            html += "<p>User Code: " + data['user_code'] ;
            // show device_code only in Device Code Leak proximity scenario
            if (data['device_code']){
                html += ", Device Code: " + data['device_code'];
            }
            html += "</p>"
            html += '<p style="text-align: left;"><span>Verification URI: </span><a href=' + data['verification_uri'] 
                        + " target='_blank'>" + data['verification_uri'] + "</a></p>";
            html += '<p style="text-align: left;"><span>Verification URI Complete: </span><a href=' + data['verification_uri_complete'] 
                        + " target='_blank'>" + data['verification_uri_complete'] + "</a></p>";
            document.getElementById('display').innerHTML = html;
            
            STARTDATE = new Date();
            TIMEOUT = data['timeout'];
            // start checking for authentication complete
            pollForSuccess(url);
        }
    });
}

// ajax post to initiate device grant at device backend
function ajaxPostJson(url, callback) {
    var request = new XMLHttpRequest();
    request.onreadystatechange = function() {
        if (request.readyState == 4 && request.status == 200) {
            try {
                var data = JSON.parse(request.responseText);
            } catch(error) {
                console.log(error.message + " in " + request.responseText)
                return;
            }
            callback(data);
        }
    }
    request.open("POST", url, true);
    request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    request.send("client_id=" + clientID);
}

// periodically check for succes of grant or display error messages corresponding to error cases
function pollForSuccess(url) {
    var successUrl = url + 'grant-successful'
    var endDate = new Date();
    var seconds = (endDate.getTime() - STARTDATE.getTime()) / 1000;
    var button = '<button onclick=deviceGrant(' + url + ')>Try again</button>';
    if(seconds > TIMEOUT) {
        document.getElementById('display').innerHTML = "<br><p>Timeout. Please try again.</p>" + button
    } else {
        setTimeout(function() {
            ajaxPostJson(successUrl, function(data) {
                console.log(data)
                if (data['state'] == 'success') {
                    document.getElementById('display').innerHTML = "<br><p>Your device is now connected to your account.</p>"
                } else if (data['state'] == 'service_unavailable') {
                    document.getElementById('display').innerHTML = "<br><p>Service Unavailable. Please try again later.</p>"  + button
                } else if (data['state'] == 'error') {
                    document.getElementById('display').innerHTML = "<br><p>Something went wrong. Please try again.</p>" + button
                } else if (data['state'] == 'timeout') {
                    document.getElementById('display').innerHTML = "<br><p>Timeout. Please try again.</p>" + button
                } else {
                    pollForSuccess(url)
                }            
            });
        }, 500);
    }
    
}