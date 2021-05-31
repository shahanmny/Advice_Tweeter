const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const querystring = require('querystring');

//Get important info from credentials.json
//callback must be base_url/receive_code
const {twitter_api_key, twitter_api_secret_key, twitter_callback_url} = require('./auth/credentials.json');
//cache.json stores the cache
const cache_file_name = './auth/cache.json';

//Info regarding the cache
const max_cache_length = 100;
let current_cache_length = 0;
let cache_used = false;
//If cache file does not exist, create and initialize the file
if(!fs.existsSync(cache_file_name)) {
    const json_object = JSON.stringify({cache: []});
    fs.writeFileSync(cache_file_name, json_object);
}

const all_sessions = [];

const port = 3000;
const server = http.createServer();

server.on('listening', listen_handler);
server.listen(port);
function listen_handler() {
    console.log(`Now Listening on Port ${port}`);
}

server.on('request', request_handler);
function request_handler(req, res) {
    console.log(`New Request from ${req.socket.remoteAddress} for ${req.url}`);
    
    //Respond with the index.html page
    if(req.url === '/') {
        const form = fs.createReadStream('html/index.html');
        res.writeHead(200, {'Content-Type': 'text/html'});
        form.pipe(res);
    }
    //Begin the process of tweeting the advice
    else if(req.url.startsWith('/tweet_advice')) {
        //create a new session and push it to all_session global array
        const session = {
            'request_token': '',
            'request_token_secret': '',
            'oauth_verifier': '',
            'access_token': '',
            'access_token_secret': '',
            'user_id': '',
            'username': '',
            'advice': '',
            'number_of_advice_requests_sent': 0
        };
        all_sessions.push(session);
        //Begin the 3 Legged OAuth Process
        send_request_token_request(res, session);   
    }
    //Receive the code from twitter api meaning that the user has given permission
    else if(req.url.startsWith('/receive_code')) {
        //Get the parameters
        const url = new URL('http://localhost'+req.url);
        const oauth_token = url.searchParams.get('oauth_token');
        const oauth_verifier = url.searchParams.get('oauth_verifier');

        //Get the user's session
        const session = all_sessions.find(s => s['request_token'] === oauth_token);

        //If there is no session return 404
        if(session == undefined) {
            console.log(`Session Not Found`);
            not_found(res, session);
        }
        //Otherwise continue with the 3 Legged OAuth Process
        else {
            session['oauth_verifier'] = oauth_verifier;
            send_access_token_request(res, session);
        } 
    }
    //If the user presses the back button then redirect them back to the index page
    else if(req.url.startsWith('/back')) {
        const twitter_base_url = twitter_callback_url.split('receive_code')[0];
        res.writeHead(302, {Location: twitter_base_url})
        .end();      
    }
    //No such path, return 404
    else {
        not_found(res, undefined);
    }

}

//Begin the 3 Legged OAuth Process
//Step 1: Get the request token(temporary token) from the twitter api
function send_request_token_request(...args) {
    console.log(`Sending Request for Request Token`);

    const token_endpoint = 'https://api.twitter.com/oauth/request_token';
    //Header must include OAuth Authorization Header
    const options = {
        method: "POST", 
        headers: {
            "Content-Type": "application/x-www-form-urlencoded", 
            "Authorization": authorization_header1('POST', token_endpoint)
        }
    }
    https.request(
        token_endpoint,
        options,
        (stream) => process_stream(stream, receive_request_token, ...args)
    ).end();
}

//Get back the request token from the twitter api
function receive_request_token(body, res, session) {
    try {
        //Add the tokens to the user's session
        const data = body.split('&')
        session['request_token'] = data[0].split('=')[1];
        session['request_token_secret'] = data[1].split('=')[1];
        //Make sure the tokens are not undefined
        if(session['request_token'] == undefined || session['request_token_secret'] == undefined) {
            throw `No Tokens`;
        }
        
        console.log(`Received Request Token from Twitter Api`);
        
        redirect_to_twitter(res, session)
    }
    catch(e) {
        console.log(`Error Did Not receive Request Token from Twitter Api`);
        not_found(res, session);
    }
}

//Step 2: Redirect the users to twitter where they can sign in and give permission
function redirect_to_twitter(res, session) {
    console.log(`Redirecting to Twitter`);
    const authorization_endpoint = `https://api.twitter.com/oauth/authorize?oauth_token=${session['request_token']}`;
    res.writeHead(302, {Location: `${authorization_endpoint}`})
        .end();
}

//Step 3: Get the access tokens from the twitter api
function send_access_token_request(res, session) {
    console.log(`Sending Request for Access Token`);

    const token_endpoint = (`https://api.twitter.com/oauth/access_token?oauth_consumer_key=${twitter_api_key}&oauth_token=${session['request_token']}&oauth_verifier=${session['oauth_verifier']}`);

    const options = {
        method: "POST", 
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    }
    https.request(
        token_endpoint,
        options,
        (stream) => process_stream(stream, receive_access_token, res, session)
    ).end();
}

//Get back the access_token
//3 Legged OAuth Completed
function receive_access_token(body, res, session) {
    try {
        //Add the Tokens to the user's session
        const data = body.split('&')
        session['access_token'] = data[0].split('=')[1];
        session['access_token_secret'] = data[1].split('=')[1];
        session['user_id'] = data[2].split('=')[1];
        session['username'] = data[3].split('=')[1];
        
        //Make sure the tokens are not undefined
        if(session['access_token'] == undefined || session['access_token_secret'] == undefined) {
            throw `No Tokens`;
        }

        console.log(`Received Access Token from Twitter Api`);

        send_advice_request(res, session);
    }
    catch {
        console.log(`Error Did Not receive Access Token from Twitter Api`);
        not_found(res, session);
    }
}

//Send a request to the second api to get the advice
function send_advice_request(res, session) {
    console.log(`Sending Advice Request to Advice Slip Api`);

    const advice_endpoint = `https://api.adviceslip.com/advice`;
    
    const options = {
        method: "GET", 
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    }
    https.request(
        advice_endpoint,
        options,
        (stream) => process_stream(stream, receive_advice_response, res, session)
    ).end();   
}

//Get back the advice
function receive_advice_response(body, res, session) {
    try {
        const data = JSON.parse(body)['slip'];
        const advice = data['advice'];
        
        //Check if Advice is not undefined
        if(advice == undefined) {
            throw `No Advice`;
        }
        
        session['advice'] = advice;
        
        console.log(`Received Advice from the Advice Slip Api`);

        //We want advice not a word, send another request to the second api again
        if(session['advice'].length < 8) {
            send_advice_request(res, session);
        }
        else {
            //If the cache is not full or has been used(A advice was taken from the cache) than add new advice to the cache
            if(current_cache_length < max_cache_length || cache_used) {
                create_advice_cache(session);
            }
            send_tweet_request(res, session);
        }
    }
    catch(e) {
        console.log(`Error Did Not Get Advice from Advice Slip Api`)
        console.log(`Advice in Cache Will Now be Used`);
        //If getting advice from the second api failed, than get the advice from the cache
        get_advice_cache(session);
        send_tweet_request(res, session);
    }
}

//Send a request to tweet the advice
function send_tweet_request(res, session) {
    console.log(`Sending Request for Tweet`);

    const post_endpoint = `https://api.twitter.com/1.1/statuses/update.json?include_entities=true`;
    const status = session['advice'].replace(/!/g, '').replace(/'/g, '').replace(/"/g, '');
    const post_data = querystring.stringify({status: status});

    const options = {
        method: "POST", 
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": authorization_header2('POST', post_endpoint, encodeURIComponent(status), session)
        }
    }
    https.request(
        post_endpoint,
        options,
        (stream) => process_stream(stream, receive_tweet_response, res, session)
    ).end(post_data);
}

//Get back the response for the tweet request
function receive_tweet_response(body, res, session) {
    try {
        const response = JSON.parse(body);
        //If there is a errors in the response check the code
        if(response['errors'] != undefined) {
            const code = response['errors'][0]['code'];
            //If the code is 187 which means duplicate advice than get new advice again
            //But if this has been tried 5 times already in this session, return 404
            if(code == 187 && session['number_of_advice_requests_sent'] < 5) {
                console.log(`Received Duplicate Advice from the Advice Slip Api, Sending Out Another Request`);
                session['number_of_advice_requests_sent']++;
                send_advice_request(res, session);
            }
            else {
                throw `Error Posting Tweet`;
            }
        }
        else {
            console.log(`Tweet Has Been Posted`);
            //Delete the session
            delete_session(session);
            //Respond with the success page
            const form = fs.createReadStream('html/success.html');
            res.writeHead(200, {'Content-Type': 'text/html'});
            form.pipe(res);
        }
    }
    catch(e) {
        console.log(`Error Posting Tweet`);
        not_found(res, session);
    }
}

//Get a piece of advice from the cache and add it to the session
function get_advice_cache(session) {
    let cache = JSON.parse(fs.readFileSync(cache_file_name));
    let cache_array = cache['cache'];
    
    session['advice'] = cache_array[Math.floor(Math.random()*cache_array.length)];

    //The cache has been used
    cache_used = true;
}

//Add a new piece of advice to the cache
function create_advice_cache(session) {
    let cache = JSON.parse(fs.readFileSync(cache_file_name));
    let cache_array = cache['cache'];
    //If the cache is full, remove the first advice in the array
    if(cache_array.length >= max_cache_length) {
        cache_array.shift();
    }
    //add the advice
    cache_array.push(session['advice']);

    current_cache_length = cache_array.length;
    fs.writeFileSync(cache_file_name, JSON.stringify(cache));

    //New advice, so cache has no longer been used
    cache_used = false;
}

//OAuth 1.0a Authorization Header for Request Token 
function authorization_header1(method, twitter_base_url) {
    //Parameters needed for the signature and for the header itself
    const parameters = {
        oauth_callback: twitter_callback_url,
        oauth_consumer_key: twitter_api_key,
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: Math.floor(Date.now()/1000),
        oauth_nonce: generate_nonce(),
        oauth_version: '1.0'
    }

    //Create a string connecting all the parameters for the signature
    let signature_base_string = `${method}&${encodeURIComponent(twitter_base_url)}`;
    Object.keys(parameters).sort().forEach(function(key) {
        if(key == 'oauth_callback') {
            signature_base_string += `&` + (encodeURIComponent(`${key}=${encodeURIComponent(parameters[key])}`));
        }
        else {
            signature_base_string += (encodeURIComponent(`&${key}=${parameters[key]}`));
        }
    });

    //Create the signature
    const signing_key = `${twitter_api_secret_key}&`;
    const oauth_signature = crypto.createHmac("sha1", signing_key).update(signature_base_string).digest().toString('base64');
    const encoded_oauth_signature = encodeURIComponent(oauth_signature);

    //Create the header and return it
    const authorization_header = `OAuth oauth_nonce="${parameters.oauth_nonce}", oauth_callback="${encodeURIComponent(parameters.oauth_callback)}", oauth_signature_method="${parameters.oauth_signature_method}", oauth_timestamp="${parameters.oauth_timestamp}", oauth_consumer_key="${parameters.oauth_consumer_key}", oauth_signature="${encoded_oauth_signature}", oauth_version="1.0"`
    return authorization_header;
}

//OAuth 1.0a Authorization Header To Post a Tweet
function authorization_header2(method, url, status, session) {
    //Get the twitter base url
    const twitter_base_url = url.split('?')[0];

    //Parameters needed for the signature and for the header itself
    const parameters = {
        include_entities: true,
        oauth_consumer_key: twitter_api_key,
        oauth_nonce: generate_nonce(),
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: Math.floor(Date.now()/1000),
        oauth_token: session['access_token'],
        oauth_version: '1.0',
        status: status
    }

    //Create a string connecting all the parameters for the signature
    let signature_base_string = `${method}&${encodeURIComponent(twitter_base_url)}`;
    Object.keys(parameters).sort().forEach((key) => {
        if(key == 'include_entities') {
            signature_base_string += `&` + (encodeURIComponent(`${key}=${parameters[key]}`));
        }
        else {
            signature_base_string += (encodeURIComponent(`&${key}=${parameters[key]}`));
        }
    });

    //Create the signature
    const signing_key = `${twitter_api_secret_key}&${session['access_token_secret']}`;
    const oauth_signature = crypto.createHmac("sha1", signing_key).update(signature_base_string).digest().toString('base64');
    const encoded_oauth_signature = encodeURIComponent(oauth_signature);

    //Create the header and return it
    const authorization_header = `OAuth oauth_consumer_key="${parameters.oauth_consumer_key}", oauth_nonce="${parameters.oauth_nonce}", oauth_signature="${encoded_oauth_signature}", oauth_signature_method="${parameters.oauth_signature_method}", oauth_timestamp="${parameters.oauth_timestamp}", oauth_token="${parameters.oauth_token}", oauth_version="${parameters.oauth_version}"`;
    return authorization_header;
}

//Generate the nonce which is needed for the authorization headers
function generate_nonce() {
    let nonce_length = 42;
    const nonce = crypto.randomBytes(Math.ceil(nonce_length * 3 / 4))
        .toString('base64')    // convert to base64 format
        .slice(0, nonce_length)// return required number of characters
        .replace(/\+/g, '0')   // replace '+' with '0'
        .replace(/\//g, '0');  // replace '/' with '0'
    return nonce;
}

//Process the stream from the post request and append it to the body and then send it to the callback
function process_stream(stream, callback, ...args) {
    let body = "";
    stream.on('data', chunk => body += chunk);
    stream.on('end', () => callback(body, ...args));
}

//Return 404 page
function not_found(res, session) {
    //If there is a session delete it
    if(session != undefined) {
        delete_session(session);
    }

    //Return 404 page
    const form = fs.createReadStream('html/error.html');
    res.writeHead(404, {'Content-Type': 'text/html'});
    form.pipe(res);
}

//Delete session from the all_session global array
function delete_session(session) {
    const index = all_sessions.indexOf(session);
    if(index > -1) {
        all_sessions.splice(index, 1);
    }
}