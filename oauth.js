/**
 * oauth.js
 * OAuth Client for Node.js
 * @author itea <iteahere@gmail.com> 2010-10-29
 * @version 0.1 2010-11-06
 * @license MIT
 * @git git://github.com/itea/oauthjs.git
 */

var http = require('http'), querystring = require('querystring'), url = require('url');
var enc = encodeURIComponent, dec = decodeURIComponent;
/**
 *
 * @param config: Object
 */
function OAuth(configuration) {
    this.config = configuration || {};
}

OAuth.prototype.acquireRequestToken = function(body, callback, ctx) {
    var urlInfo = url.parse(this.config.requestTokenURI);

    var client = OAuth.createClient(urlInfo);
    
    var oauthHeader = OAuth.buildRequestAuthorizationHeader(this);
    var signatureBaseString = OAuth.generateSignatureBaseString('POST',
        this.config.requestTokenURI, oauthHeader, body);
    //console.log('baseString: '+ signatureBaseString);
    oauthHeader['oauth_signature'] = OAuth.sign(this, signatureBaseString);
    
    var body = querystring.stringify(body);
    var headers = {
        'Host': urlInfo.hostname,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': body.length,
        'Authorization': OAuth.toAuthorizationHeaderString(oauthHeader),
    };
    //console.log(JSON.stringify(headers));
    var request = client.request('POST', urlInfo.pathname, headers);
    request.write(body);
    request.end();
    
    var oauth = this;
    request.on('response', function(response) {
      	//console.log(response);
        if(+response.statusCode === 200) {
            response.setEncoding('utf8');
            response.on('data', function(data) {
          		//console.log(data);
                OAuth.parseOAuthBody(data.toString(), oauth);
                callback && callback.call(ctx, oauth);
            });
        } else {
            console.log('ERROR: '+ response.statusCode);
            response.on('data', function(data) {
                console.log('ERROR-BODY: '+ data);
                var err = new Error(data.toString());
                err.statusCode = response.statusCode;
                callback && callback.call(ctx, err);
            });
        }
    });
    return this;
};

OAuth.prototype.getAuthorizeTokenURI = function(parameters){
    parameters = parameters || {};
    var s = [];
    s.push('oauth_token='+ enc(this.oauthToken));
    s.push('oauth_callback='+ enc(this.config.callbackURI));
    for(var p in parameters) s.push([p, '=', enc(parameters[p])].join(''));
    return [this.config.authorizeTokenURI, '?', s.join('&')].join('');
};

OAuth.prototype.setOAuthVerifier = function(oauthVerifier){
    this.oauthVerifier = oauthVerifier;
    return this;
};

OAuth.prototype.acquireAccessToken = function(callback, ctx){
    var urlInfo = url.parse(this.config.accessTokenURI);
    var client = OAuth.createClient(urlInfo);
    var oauthHeader = OAuth.buildAccessAuthorizationHeader(this);
    var signatureBaseString = OAuth.generateSignatureBaseString('POST',
        this.config.accessTokenURI, oauthHeader);
    oauthHeader['oauth_signature'] = OAuth.sign(this, signatureBaseString);
    
    var headers = {
        'Host': urlInfo.hostname,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': 0,
        'Authorization': OAuth.toAuthorizationHeaderString(oauthHeader)
    };
    var request = client.request('POST', urlInfo.pathname, headers);
    request.end();

    var oauth = this;
    request.on('response', function(response) {
        if(+response.statusCode === 200) {
            response.setEncoding('utf8');
            response.on('data', function(data) {
                OAuth.parseOAuthBody(data.toString(), oauth);
                callback && callback.call(ctx, oauth);
                //console.log(data.toString());
            });
        } else {
            console.log('ERROR: '+ response.statusCode);
            response.on('data', function(data) {
                console.log('ERROR-BODY: '+ data);
                var err = new Error(data.toString());
                err.statusCode = response.statusCode;
                callback && callback.call(ctx, err);
            });
        }
    });
    return this;
};

/**
 * Generate Authorization header String for data access api request
 */
OAuth.prototype.generateAuthorizationString = function(method, uri, parameters) {
    var oauthHeader = OAuth.buildAuthorizationHeader(this);
    var signatureBaseString = OAuth.generateSignatureBaseString(method, uri, oauthHeader, parameters);
    oauthHeader['oauth_signature'] = OAuth.sign(this, signatureBaseString);
    return OAuth.toAuthorizationHeaderString(oauthHeader);
};

OAuth.prototype.debugGenerateBaseString = function(method, uri, parameters) {
    var oauthHeader = OAuth.buildAuthorizationHeader(this);
    return OAuth.generateSignatureBaseString(method, uri, oauthHeader, parameters);
};

/* -------------------------------- */
OAuth.createClient = function(info) {
    return http.createClient(info.port || 80, info.hostname, false);
};

OAuth.parseOAuthBody = function(body, oauth) {
    oauth = oauth || {};
    var b = querystring.parse(body);
    oauth.oauthToken = b.oauth_token;
    oauth.oauthTokenSecret = b.oauth_token_secret;
    return oauth;
};

/**
 * Build Authorization header string for request token request
 */
OAuth.buildRequestAuthorizationHeader = function(oauth) {
    var config = oauth.config;
    return {
        'oauth_consumer_key': config.consumerKey,
        'oauth_version': '1.0',
        'oauth_callback': config.callbackURI,
        'oauth_timestamp': (new Date().valueOf()/1000).toFixed().toString(),
        'oauth_nonce': new Date().valueOf().toString(),
        'oauth_signature_method': config.signatureMethod
    };
};

/**
 * Build Authorization header string for access token request
 */
OAuth.buildAccessAuthorizationHeader = function(oauth) {
    var config = oauth.config;
    return {
        'oauth_consumer_key': config.consumerKey,
        'oauth_version': '1.0',
        'oauth_timestamp': (new Date().valueOf()/1000).toFixed().toString(),
        'oauth_nonce': new Date().valueOf().toString(),
        'oauth_signature_method': config.signatureMethod,
        'oauth_verifier': oauth.oauthVerifier,
        'oauth_token': oauth.oauthToken
    };
};

/**
 * Build Authorization header string for data access api request
 */
OAuth.buildAuthorizationHeader = function(oauth) {
    var config = oauth.config;
    return {
        'oauth_consumer_key': config.consumerKey,
        'oauth_version': '1.0',
        'oauth_timestamp': (new Date().valueOf()/1000).toFixed().toString(),
        'oauth_signature_method': config.signatureMethod,
        'oauth_token': oauth.oauthToken
    };
};

OAuth.toAuthorizationHeaderString = function(header) {
    var a = [];
    for(var v in header) {
        a.push([v, '="', enc(header[v]), '"'].join(''));
    }
    return 'OAuth ' + a.join(',');
};

/**
 * @param method: string ('POST' or 'GET')
 * @param baseURL: string
 * @param headers: header parameters object
 * @param bodys: body parameter object
 */
OAuth.generateSignatureBaseString = function(method, uri, headers, bodys) {
    var params = [], uri = encodeURI(uri);
    headers = headers || {};
    bodys = bodys || {};

    for(var idx in headers) {
        params.push([idx, enc(headers[idx])].join('='));
    }
    for(var idx in bodys) {
        params.push([enc(idx), enc(bodys[idx])].join('='));
    }
    return [method.toUpperCase(), enc(uri.replace(/\?.+$/, '')), enc(params.sort().join('&'))].join('&');
};

OAuth.sign = function(oauth, baseString) {
    var method = oauth.config.signatureMethod;
    var key = [enc(oauth.config.consumerSecret ||''), '&', enc(oauth.oauthTokenSecret ||'')].join('');
    if(method === 'HMAC-SHA1') return OAuth.signHmacSha1(baseString, key);
    else if(method === 'RSA-SHA1') return null;
};

OAuth.signHmacSha1 = function(baseString, key) {
    var signer = require('crypto').createHmac('SHA1', key);
    signer.update(baseString);
    return signer.digest('base64');
};

module.exports = OAuth;

