/**
 * Created with JetBrains WebStorm.
 * User: Lokesh
 * Date: 10/7/12
 * Time: 8:18 AM
 * To change this template use File | Settings | File Templates.
 */
var express     = require('express'),
    util        = require('util'),
    fs          = require('fs'),
    OAuth       = require('oauth').OAuth,
    query       = require('querystring'),
    url         = require('url'),
    http        = require('http'),
    https       = require('https'),
    crypto      = require('crypto'),
    redis       = require('redis'),
    RedisStore  = require('connect-redis')(express),
    passport    = require('passport'),
    IntuitStrategy = require('passport-intuit').Strategy;

// Configuration
try {
    var configJSON = fs.readFileSync(__dirname + "/config.json");
    var config = JSON.parse(configJSON.toString());
} catch(e) {
    console.error("File config.json not found or is invalid.  Try: `cp config.json.sample config.json`");
    process.exit(1);
}

//proxy definition
/*var proxy={
    host:'127.0.0.1',
    port:8888,
    localAddress: '127.0.0.1'
};
*/
var proxy=null;
//
// Redis connection
//
var defaultDB = '0';
var db;

if (process.env.REDISTOGO_URL) {
    var rtg   = require("url").parse(process.env.REDISTOGO_URL);
    db = require("redis").createClient(rtg.port, rtg.hostname);
    db.auth(rtg.auth.split(":")[1]);
} else {
    db = redis.createClient(config.redis.port, config.redis.host);
    db.auth(config.redis.password);
}

db.on("error", function(err) {
    if (config.debug) {
        console.log("Error " + err);
    }
});

//
// Load API Configs
//
var apisConfig;
fs.readFile(__dirname +'/public/data/apiconfig.json', 'utf-8', function(err, data) {
    if (err) throw err;
    apisConfig = JSON.parse(data);
    if (config.debug) {
        console.log(util.inspect(apisConfig));
    }
});

var app = module.exports = express.createServer();

if (process.env.REDISTOGO_URL) {
    var rtg   = require("url").parse(process.env.REDISTOGO_URL);
    config.redis.host = rtg.hostname;
    config.redis.port = rtg.port;
    config.redis.password = rtg.auth.split(":")[1];
}

app.configure(function() {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(express.logger());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser());
    app.use(express.session({
        secret: config.sessionSecret,
        store:  new RedisStore({
            'host':   config.redis.host,
            'port':   config.redis.port,
            'pass':   config.redis.password,
            'maxAge': 1209600000
        })
    }));
    app.use(passport.initialize());

    app.use(app.router);
    app.use(express.static(__dirname + '/public'));
});

app.configure('development', function() {
    app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function() {
    app.use(express.errorHandler());
});

//passport
passport.serializeUser(function(user, done) {
   // db.set(user.emails[0].value, JSON.stringify(user), redis.print);
    done(null, user);
});

passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

//middlewares

function getSavedInfo(req, res, next){
    var apiName = req.params.api;
    if(req.session.loggedin)
        key = req.session.passport.user.emails[0].value + ":" + apiName;
    else
        key = req.sessionID + ':' + apiName;
    db.mget([
        key + ':accessToken',
        key + ':accessTokenSecret',
        key + ':apiKey',
        key + ':apiSecret',
        key + ':params',
        key + ':savedParams',
        key + ':savedRequestBody',
        key + ':savedHeaders'
    ], function(err, result) {
        if(!req.session[apiName]){
            req.session[apiName] = {};
        }
        if (err) {
            console.log(util.inspect(err));
            next();
        }
        else if(result[0] != null && result[1] != null && result[2] != null && result[3] != null){

            req.session[apiName].authed = true
            if(!apisConfig[apiName])
                apisConfig[apiName]={};
            req.session[apiName].defaultAccessKey=result[0];
            req.session[apiName].defaultAccessSecret=result[1];
            req.session[apiName].defaultKey=result[2];
            req.session[apiName].defaultSecret=result[3];
        }
        else {
    //        req.session[apiName] = {};
        }

        if(result[4]!=null){
            req.session[apiName].params = JSON.parse(result[4]);
        }
        else
            req.session[apiName].params = {};
        if(result[5]!=null){
            req.session[apiName].savedParams = JSON.parse(result[5]);
        }
        else
            req.session[apiName].savedParams = {};
        if(result[6]!=null){
            req.session[apiName].savedRequestBody = JSON.parse(result[6]);
        }
        else
            req.session[apiName].savedRequestBody = {};
        if(result[7]!=null){
            req.session[apiName].savedHeaders = JSON.parse(result[7]);
        }
        else
            req.session[apiName].savedHeaders={};

        next();
    });
}

function saveRequest(req, res, next) {
    var apiName = req.body.apiName;
    if(req.session.loggedin)
        key = req.session.passport.user.emails[0].value + ':' + apiName;
    // Unique key using the username and API name to store tokens and secrets
    else
        key = req.sessionID + ':' + apiName;
    // Unique key using the sessionID and API name to store tokens and secrets

    req.session[req.body.apiName].savedParams[req.body.endpointName+':'+req.body.methodName]=req.body.params
    db.set(key + ':savedParams' , JSON.stringify(req.session[req.body.apiName].savedParams), redis.print);

    req.session[req.body.apiName].savedRequestBody[req.body.endpointName+':'+req.body.methodName]=req.body.requestBody;
    db.set(key + ':savedRequestBody' , JSON.stringify(req.session[req.body.apiName].savedRequestBody), redis.print);

    req.session[req.body.apiName].savedHeaders[req.body.endpointName+':'+req.body.methodName]=req.body.headers;
    db.set(key + ':savedHeaders' , JSON.stringify(req.session[req.body.apiName].savedHeaders), redis.print);
    next();
}

function handleCredentials(req, res, next){
    if(req.body.action && req.body.action == "remove"){
        removeCredentials(req, res, next);
    }
 /* //Get Default
        else if(req.body.action && req.body.action == "getDefault"){
        var apiName = req.body.apiName;
        if(apisConfig[apiName].default)
        res.send({ 'default': apisConfig[apiName].default });
    }
 */
    else if(!req.body.accessKey || !req.body.accessSecret){
        oauth(req, res, next);
    }
    else{
        saveCredentials(req, res, next);
    }
}

function removeCredentials(req, res, next) {
    var apiName = req.body.apiName;
    if(req.session.loggedin)
        key = req.session.passport.user.emails[0].value + ':' + apiName;
    // Unique key using the username and API name to store tokens and secrets
    else
        key = req.sessionID + ':' + apiName;
    db.del(key + ':apiKey');
    db.del(key + ':apiSecret');
    db.del(key + ':requestToken');
    db.del(key + ':requestTokenSecret');
    db.del(key + ':accessToken');
    db.del(key + ':accessTokenSecret');

    req.session[apiName].authed = false;
    req.session[apiName].default = false;
    next();
}

function saveCredentials(req, res, next){
    var apiName = req.body.apiName;
    if(req.session.loggedin)
        key = req.session.passport.user.emails[0].value + ':' + apiName;
    // Unique key using the username and API name to store tokens and secrets
    else
        key = req.sessionID + ':' + apiName;
    if(req.body.key && req.body.secret && req.body.accessKey && req.body.accessSecret){
        db.set(key + ':apiKey', req.body.key, redis.print);
        db.set(key + ':apiSecret', req.body.secret, redis.print);
        db.set(key + ':accessToken', req.body.accessKey, redis.print);
        db.set(key + ':accessTokenSecret', req.body.accessSecret, redis.print);
        if(!req.session[apiName])
            req.session[apiName]={};
        req.session[apiName].authed = true;
    }
    next();
}

function oauth(req, res, next){
    console.log('OAuth process started');
    var apiName = req.body.apiName,
        apiConfig = apisConfig[apiName];

    if (apiConfig.oauth) {
        var apiKey = req.body.apiKey || req.body.key,
            apiSecret = req.body.apiSecret || req.body.secret,
            refererURL = url.parse(req.headers.referer),
            callbackURL = refererURL.protocol + '//' + refererURL.host + '/authSuccess/' + apiName,
            oa = new OAuth(apiConfig.oauth.requestURL,
                apiConfig.oauth.accessURL,
                apiKey,
                apiSecret,
                apiConfig.oauth.version,
                callbackURL,
                apiConfig.oauth.crypt);
        if (config.debug) {
            console.log('OAuth type: ' + apiConfig.oauth.type);
            console.log('Method security: ' + req.body.oauth);
            console.log('Session authed: ' + req.session[apiName]);
            console.log('apiKey: ' + apiKey);
            console.log('apiSecret: ' + apiSecret);
        };

        // Check if the API even uses OAuth, then if the method requires oauth, then if the session is not authed
        if (apiConfig.oauth.type == 'three-legged' && req.body.oauth == 'authrequired' && (!req.session[apiName] || !req.session[apiName].authed)) {
            if (config.debug) {
                console.log('req.session: ' + util.inspect(req.session));
                console.log('headers: ' + util.inspect(req.headers));
                console.log('sessionID: ' + util.inspect(req.sessionID));
            };

            oa.getOAuthRequestToken(function(err, oauthToken, oauthTokenSecret, proxy, results) {
                if (err) {
                    res.send("Error getting OAuth request token : " + util.inspect(err), 500);
                } else {
                    var key;
                    if(req.session.loggedin)
                        key = req.session.passport.user.emails[0].value + ':' + apiName;
                    // Unique key using the username and API name to store tokens and secrets
                    else
                        key = req.sessionID + ':' + apiName;
                    // Unique key using the sessionID and API name to store tokens and secrets

                    db.set(key + ':apiKey', apiKey, redis.print);
                    db.set(key + ':apiSecret', apiSecret, redis.print);

                    db.set(key + ':requestToken', oauthToken, redis.print);
                    db.set(key + ':requestTokenSecret', oauthTokenSecret, redis.print);

                    res.send({ 'signin': apiConfig.oauth.signinURL + oauthToken });
                }
            });
        } else if (apiConfig.oauth.type == 'two-legged' && req.body.oauth == 'authrequired') {
            // Two legged stuff... for now nothing.
            next();
        } else {
            next();
        }
    } else {
        next();
    }
}

function oauthSuccess(req, res, next){
    var oauthRequestToken,
        oauthRequestTokenSecret,
        apiKey,
        apiSecret,
        apiName = req.params.api,
        apiConfig = apisConfig[apiName];

    var key;
    if(req.session.loggedin){
        key = req.session.passport.user.emails[0].value  + ':' + apiName;
    }
    else {
        key = req.sessionID + ':' + apiName; // Unique key using the sessionID and API name to store tokens and secrets
    }
    if (config.debug) {
        console.log('apiName: ' + apiName);
        console.log('key: ' + key);
        console.log(util.inspect(req.params));
    };
    db.mget([
        key + ':requestToken',
        key + ':requestTokenSecret',
        key + ':apiKey',
        key + ':apiSecret'
    ], function(err, result) {
        if (err) {
            console.log(util.inspect(err));
        }
        oauthRequestToken = result[0],
            oauthRequestTokenSecret = result[1],
            apiKey = result[2],
            apiSecret = result[3];

        if (config.debug) {
            console.log(util.inspect(">>"+oauthRequestToken));
            console.log(util.inspect(">>"+oauthRequestTokenSecret));
            console.log(util.inspect(">>"+req.query.oauth_verifier));
        };
        var oa = new OAuth(apiConfig.oauth.requestURL,
            apiConfig.oauth.accessURL,
            apiKey,
            apiSecret,
            apiConfig.oauth.version,
            null,
            apiConfig.oauth.crypt);

        if (config.debug) {
            console.log(util.inspect(oa));
        };

        oa.getOAuthAccessToken(oauthRequestToken, oauthRequestTokenSecret, req.query.oauth_verifier, proxy, function(error, oauthAccessToken, oauthAccessTokenSecret, results) {
            if (error) {
                res.send("Error getting OAuth access token : " + util.inspect(error) + "["+oauthAccessToken+"]"+ "["+oauthAccessTokenSecret+"]"+ "["+util.inspect(results)+"]", 500);
            } else {
                if (config.debug) {
                    console.log('results: ' + util.inspect(results));
                };
                db.mset([key + ':accessToken', oauthAccessToken,
                    key + ':accessTokenSecret', oauthAccessTokenSecret,
                    key + ':params', JSON.stringify(req.query)
                ], function(err, results2) {
                    req.session[apiName] = {};
                    req.session[apiName].authed = true;
					req.session[apiName].params = req.query;
                    if (config.debug) {
                        console.log('session[apiName].authed: ' + util.inspect(req.session));
                    };

                    next();
                });
            }
        });
    });
}

function processRequest(req, res, next) {
    if (config.debug) {
        console.log(util.inspect(req.body, null, 3));
    };

    var reqQuery = req.body,
        methodURL = reqQuery.methodUri,
        httpMethod = reqQuery.httpMethod,
        apiKey = reqQuery.apiKey,
        apiSecret = reqQuery.apiSecret,
        apiName = reqQuery.apiName,
        headers = reqQuery.headers
    apiConfig = apisConfig[apiName];

    var params = new Object();
    if(reqQuery.params){
        for (var item in reqQuery.params){
            params[item]=reqQuery.params[item];
        }
    }


    var key;
    if(req.session.loggedin)
        key = req.session.passport.user.emails[0].value + ':' + apiName;
    else
        key = req.sessionID + ':' + apiName;

    // Replace placeholders in the methodURL with matching params
    for (var param in params) {
        if (params.hasOwnProperty(param)) {
            if (params[param] !== '') {
                // URL params are prepended with ":"
                var regx = new RegExp(':' + param);

                // If the param is actually a part of the URL, put it in the URL and remove the param
                if (!!regx.test(methodURL)) {
                    methodURL = methodURL.replace(regx, params[param]);
                    delete params[param];
                }
            } else {
                delete params[param]; // Delete blank params
            }
        }
    }

    var baseHostInfo = apiConfig.baseURL.split(':');
    var baseHostUrl = baseHostInfo[0],
        baseHostPort = (baseHostInfo.length > 1) ? baseHostInfo[1] : "";

    var paramString = query.stringify(params),
        privateReqURL = apiConfig.protocol + '://' + apiConfig.baseURL + apiConfig.privatePath + methodURL + ((paramString.length > 0) ? '?' + paramString : ""),
        options = {
            headers: {},
            protocol: apiConfig.protocol + ':',
            host: baseHostUrl,
            port: baseHostPort,
            method: httpMethod,
            path: apiConfig.publicPath + methodURL// + ((paramString.length > 0) ? '?' + paramString : "")
        };

    var requestBody = "";

    if (['POST','DELETE','PUT'].indexOf(httpMethod) !== -1 && !req.body.requestBody) {
        requestBody = query.stringify(params);
    }
    else if(['POST','DELETE','PUT'].indexOf(httpMethod) !== -1 && req.body.requestBody) {
        requestBody = req.body.requestBody;
    }

    if (apiConfig.oauth) {
        console.log('Using OAuth');

        // Three legged OAuth
        if (apiConfig.oauth.type == 'three-legged' && (reqQuery.oauth == 'authrequired' || (req.session[apiName] && req.session[apiName].authed))) {
            if (config.debug) {
                console.log('Three Legged OAuth');
            };

            db.mget([key + ':apiKey',
                key + ':apiSecret',
                key + ':accessToken',
                key + ':accessTokenSecret'
            ],
                function(err, results) {

                    var apiKey = results[0],
                        apiSecret = results[1],
                        accessToken = results[2],
                        accessTokenSecret = results[3];
                    if(config.debug) {
                        console.log("apiKey:"+ apiKey);
                        console.log("apiSecret:" +apiSecret);
                        console.log("accessToken:" +accessToken);
                        console.log("accessTokenSecret:" +accessTokenSecret);
                    };
                    var oa = new OAuth(apiConfig.oauth.requestURL || null,
                        apiConfig.oauth.accessURL || null,
                        apiKey || null,
                        apiSecret || null,
                        apiConfig.oauth.version || null,
                        null,
                        apiConfig.oauth.crypt);

                    oa.getProtectedResource(privateReqURL, httpMethod, accessToken, accessTokenSecret, requestBody, headers, proxy, function (error, data, response) {
                        req.call = privateReqURL;

                        // console.log(util.inspect(response));
                        if (error) {
                            console.log('Got error: ' + util.inspect(error));

                            req.resultHeaders = response.headers;
                            if (error.data == 'Server Error' || error.data == '') {
                                req.result = 'Server Error';
                            } else {
                                req.result = error.data;
                            }

                            res.statusCode = error.statusCode

                            next();
                        } else {
                            req.resultHeaders = response.headers;
							if(response.headers['content-type'].indexOf("xml") >=0 || data == "") {
								req.result = data;
							}
							else
								req.result = JSON.parse(data);
                            next();
                        }
                    });
                }
            );
        } else if (apiConfig.oauth.type == 'two-legged' && reqQuery.oauth == 'authrequired') { // Two-legged
            if (config.debug) {
                console.log('Two Legged OAuth');
            };

            var body,
                oa = new OAuth(null,
                    null,
                    apiKey || null,
                    apiSecret || null,
                    apiConfig.oauth.version || null,
                    null,
                    apiConfig.oauth.crypt);

            var resource = options.protocol + '://' + options.host + options.path,
                cb = function(error, data, response) {
                    if (error) {
                        if (error.data == 'Server Error' || error.data == '') {
                            req.result = 'Server Error';
                        } else {
                            body = error.data;
                        }

                        res.statusCode = error.statusCode;

                    } else {
                        var responseContentType = response.headers['content-type'];

                        switch (true) {
                            case /application\/javascript/.test(responseContentType):
                            case /text\/javascript/.test(responseContentType):
                            case /application\/json/.test(responseContentType):
                                body = JSON.parse(data);
                                break;
                            case /application\/xml/.test(responseContentType):
                            case /text\/xml/.test(responseContentType):
                            default:
                        }
                    }

                    // Set Headers and Call
                    if (response) {
                        req.resultHeaders = response.headers || 'None';
                    } else {
                        req.resultHeaders = req.resultHeaders || 'None';
                    }

                    req.call = url.parse(options.host + options.path);
                    req.call = url.format(req.call);

                    // Response body
                    req.result = body;

                    next();
                };

            switch (httpMethod) {
                case 'GET':
                    console.log(resource);
                    oa.get(resource, '', '',cb);
                    break;
                case 'PUT':
                case 'POST':
                    oa.post(resource, '', '', JSON.stringify(obj), null, cb);
                    break;
                case 'DELETE':
                    oa.delete(resource,'','',cb);
                    break;
            }

        } else {
            // API uses OAuth, but this call doesn't require auth and the user isn't already authed, so just call it.
            unsecuredCall();
        }
    } else {
        // API does not use authentication
        unsecuredCall();
    }

    // Unsecured API Call helper
    function unsecuredCall() {
        console.log('Unsecured Call');

        if (['POST','PUT','DELETE'].indexOf(httpMethod) === -1) {
            options.path += ((paramString.length > 0) ? '?' + paramString : "");
        }

        // Add API Key to params, if any.
        if (apiKey != '' && apiKey != 'undefined' && apiKey != undefined) {
            if (options.path.indexOf('?') !== -1) {
                options.path += '&';
            }
            else {
                options.path += '?';
            }
            options.path += apiConfig.keyParam + '=' + apiKey;
        }

        // Perform signature routine, if any.
        if (apiConfig.signature) {
            if (apiConfig.signature.type == 'signed_md5') {
                // Add signature parameter
                var timeStamp = Math.round(new Date().getTime()/1000);
                var sig = crypto.createHash('md5').update('' + apiKey + apiSecret + timeStamp + '').digest(apiConfig.signature.digest);
                options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
            }
            else if (apiConfig.signature.type == 'signed_sha256') { // sha256(key+secret+epoch)
                // Add signature parameter
                var timeStamp = Math.round(new Date().getTime()/1000);
                var sig = crypto.createHash('sha256').update('' + apiKey + apiSecret + timeStamp + '').digest(apiConfig.signature.digest);
                options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
            }
        }

        // Setup headers, if any
        if (reqQuery.headerNames && reqQuery.headerNames.length > 0) {
            if (config.debug) {
                console.log('Setting headers');
            };
            var headers = {};

            for (var x = 0, len = reqQuery.headerNames.length; x < len; x++) {
                if (config.debug) {
                    console.log('Setting header: ' + reqQuery.headerNames[x] + ':' + reqQuery.headerValues[x]);
                };
                if (reqQuery.headerNames[x] != '') {
                    headers[reqQuery.headerNames[x]] = reqQuery.headerValues[x];
                }
            }

            options.headers = headers;
        }

        //TODO: FIX headers for unsecured call
        if (!options.headers['Content-Length']) {
            if (requestBody) {
                options.headers['Content-Length'] = requestBody.length;
            }
            else {
                options.headers['Content-Length'] = 0;
            }
        }

        if (requestBody) {
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }

        if (config.debug) {
            console.log(util.inspect(options));
        };

        var doRequest;
        if (options.protocol === 'https' || options.protocol === 'https:') {
            console.log('Protocol: HTTPS');
            options.protocol = 'https:'
            doRequest = https.request;
        } else {
            console.log('Protocol: HTTP');
            doRequest = http.request;
        }

        // API Call. response is the response from the API, res is the response we will send back to the user.
        var apiCall = doRequest(options, function(response) {
            response.setEncoding('utf-8');

            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(response.headers));
                console.log('STATUS CODE: ' + response.statusCode);
            };

            res.statusCode = response.statusCode;

            var body = '';

            response.on('data', function(data) {
                body += data;
            })

            response.on('end', function() {
                delete options.agent;

                var responseContentType = response.headers['content-type'];

                switch (true) {
                    case /application\/javascript/.test(responseContentType):
                    case /application\/json/.test(responseContentType):
                        console.log(util.inspect(body));
                        // body = JSON.parse(body);
                        break;
                    case /application\/xml/.test(responseContentType):
                    case /text\/xml/.test(responseContentType):
                    default:
                }

                // Set Headers and Call
                req.resultHeaders = response.headers;
                req.call = url.parse(options.host + options.path);
                req.call = url.format(req.call);

                // Response body
                req.result = body;

                console.log(util.inspect(body));

                next();
            })
        }).on('error', function(e) {
                if (config.debug) {
                    console.log('HEADERS: ' + JSON.stringify(res.headers));
                    console.log("Got error: " + e.message);
                    console.log("Error: " + util.inspect(e));
                };
            });

        if (requestBody) {
            apiCall.end(requestBody, 'utf-8');
        }
        else {
            apiCall.end();
        }
    }
}

// Dynamic Helpers
// Passes variables to the view
app.dynamicHelpers({
    defaultParams: function(req, res) {
        if(req.params.api && req.session[req.params.api] && req.session[req.params.api]['params'])
            return req.session[req.params.api]['params'];
    },
    HelperParams: function(req, res) {
        if(req.params.api && req.session[req.params.api] && req.session[req.params.api]['savedParams'])
            return req.session[req.params.api]['savedParams'];
    },
    HelperRequestBody: function(req, res) {
        if(req.params.api && req.session[req.params.api] && req.session[req.params.api]['savedRequestBody'])
            return req.session[req.params.api]['savedRequestBody'];
    },
    defaultHeaders: function(req, res) {
    if(req.params.api && req.session[req.params.api] && req.session[req.params.api]['headers'])
        return req.session[req.params.api]['headers'];
},
    HelperHeaders: function(req, res) {
        if(req.params.api && req.session[req.params.api] && req.session[req.params.api]['savedHeaders'])
            return req.session[req.params.api]['savedHeaders'];
    },
    session: function(req, res) {
        // If api wasn't passed in as a parameter, check the path to see if it's there
        if (!req.params.api) {
            pathName = req.url.replace('/','');
            // Is it a valid API - if there's a config file we can assume so
            fs.stat(__dirname + '/public/data/' + pathName + '.json', function (error, stats) {
                if (stats) {
                    req.params.api = pathName;
                }
            });
        } else if(req.session[req.params.api]) {
            return req.session[req.params.api];
        }

        return req.session;
    },
    apiInfo: function(req, res) {
        if (req.params.api) {
            return apisConfig[req.params.api];
        } else {
            return apisConfig;
        }
    },
    loginInfo:function(req, res) {
        if(req.session.passport && req.session.passport.user)
            return req.session.passport.user;
    },
    authStatus: function(req, res) {
        var status = false;
        if(req.session[req.params.api] && req.session[req.params.api].authed)
            status=true;
        return status;
    },
    apiName: function(req, res) {
        if (req.params.api) {
            return req.params.api;
        }
    },
    apiDefinition: function(req, res) {
        if (req.params.api) {
            var data = fs.readFileSync(__dirname + '/public/data/' + req.params.api + '.json');
            return JSON.parse(data);
        }
    }
});

app.get('/', function(req, res) {
    res.render('listAPIs', {
        title: config.title
    });
});

app.post('/processReq', saveRequest, oauth, processRequest, function(req, res) {
    var result = {
        headers: req.resultHeaders,
        response: req.result,
        call: req.call,
        code: req.res.statusCode
    };

    res.send(result);
});

app.all('/credential', handleCredentials, function(req, res){
    res.send({});
});

// OAuth callback page, closes the window immediately after storing access token/secret
app.get('/authSuccess/:api', oauthSuccess, function(req, res) {
    res.render('authSuccess', {
        title: 'OAuth Successful'
    });
});

app.get('/openid/intuit',
    passport.authenticate('intuit', { failureRedirect: '/' }),
    function(req, res) {
        res.redirect('/');
    });

app.get('/openid/intuit/return',
    passport.authenticate('intuit', { failureRedirect: '/' }),
    function(req, res) {
        if(req.session.passport.user)
            req.session.loggedin = true;
        res.redirect('back');
    });

app.get('/logout', function(req, res){
    req.session.loggedin = false
    req.logout();
    res.redirect('back');
});

// API shortname, all lowercase
app.get('/:api([^\.]+)', getSavedInfo, function(req, res) {
    req.params.api=req.params.api.replace(/\/$/,'');
    res.render('api');
});

// Use the IntuitStrategy within Passport.
//   Strategies in passport require a `validate` function, which accept
//   credentials (in this case, an OpenID identifier and profile), and invoke a
//   callback with a user object.
passport.use(new IntuitStrategy({
        returnURL: 'http://'+config.address+':'+config.port+'/openid/intuit/return',
        realm: 'http://'+config.address+':'+config.port+'/'
    },
    function(identifier, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Intuit profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Intuit account with a user record in your database,
            // and return that user instead.
            profile.identifier = identifier;
            return done(null, profile);
        });
    }
));

if (!module.parent) {
    var port = process.env.PORT || config.port;
    app.listen(port);
    console.log("Express server listening on port %d", app.address().port);
}
