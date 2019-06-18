
/* Load the gapi.client library */
function start() {
    gapi.load('auth2', function() {
        auth2 = gapi.auth2.init({
            client_id: '964370231865-gju84d1v4el8prmark3svltttebmk0av.apps.googleusercontent.com'
        });
    });
}

/* Process authentication result */
function logInCallback(authResult) {
    if (authResult['code']) {
        var $gLoginButton = $('#gLoginButton');
        $gLoginButton.attr('style', 'display: none');

        var state = $gLoginButton.data('state');

        $.ajax({
            type: 'POST',
            url: '/google-login?state=' + state,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            },
            contentType: 'application/octet-stream; charset=utf-8',
            success: function(result) {
                if (result) {
                    console.log("Logged In");
                    window.location.href = "/";
                } else if (authResult['error']) {
                    displayMessage('User authorization failed.');
                    console.log('There was an error: ' + authResult['error']);
                } else {
                    displayMessage('Failed to make a server-side call.');
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                displayMessage('Authorization request failed: ' + errorThrown);
            },
            processData:false,
            data: authResult['code']
        });
    } else {
        // handle error
        displayMessage('Failed to make a server-side call. Check sign in configuration and console.');
    }
}

/* Log Google account user out */
function logout() {
    $('#logout-info').hide();

    $.ajax({
        type: 'GET',
        url: '/google-logout',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        },
        contentType: 'application/octet-stream; charset=utf-8',
        success: function(result) {
            if (result) {
            console.log("Logged Out");
                window.location.href = "/";
            } else if (authResult['error']) {
                displayMessage('User logout failed.');
                console.log('There was an error: ' + authResult['error']);
            } else {
                displayMessage('Failed to make a server-side call.');
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            displayMessage('Log out request failed: ' + errorThrown);
        }
    });
}

/* Display messages and erros */
function displayMessage(message) {
    $('#message').html(message);
    $('#login-back').css('display', 'inline-block');
}

/* Bind button events */
$(document).ready(function() {
    var $gLoginButton = $('#gLoginButton');
    var $gLogoutButton = $('#gLogoutButton');

    if ($gLoginButton.length > 0) {
        $gLoginButton.click(function() {
            auth2.grantOfflineAccess().then(logInCallback);
        });
    }

    if ($gLogoutButton.length > 0) {
        $gLogoutButton.show();
        $gLogoutButton.click(logout);
    }
});