#!/usr/local/bin/node
var OAuth = require('./oauth').OAuth;

var fs = require('fs');
var qs = require('querystring');
var url = require('url');
var http = require('http');
var path = require('path');
var crypto = require('crypto');
var Cookies = require('./cookies');
var mime = require('./mime');
var config = require('./config');

var sessions = {};
var session_seq = Math.floor(Math.random()*1000000);

function resetSessionTimeout(session){
    if(session.timeoutId){
    	clearTimeout(session.timeoutId);
    }
    session.timeoutId = setTimeout(function(){
        sessions[sid] = null;
    },session.timeout);
}

function getSession(cookies){
    var sid = cookies.get("session_id");
    if(sid){
        var session = sessions[sid];
        if(session){
        	resetSessionTimeout(session);
            return session.value;
        }
    }
    return null;
}

function setSession(cookies,val){
    var sid = cookies.get("session_id");
    if(sid){
        var session = sessions[sid];
        if(session){
        	resetSessionTimeout(session);
            session.value = val;
            return;
        }
    }
    var hmac = crypto.createHmac("sha1", "lalslslsls");
    hmac.update(String(session_seq++));
    sid = hmac.digest('hex');
    cookies.set("session_id",sid);
    var session = {
        timeout : 3600000,
        value : val,
    };
    sessions[sid] = session;
    resetSessionTimeout(session);
}

function login(req,resp){
	var oa = new OAuth(config.oauth);
    setSession(req.cookies,oa);
    oa.acquireRequestToken(null, function(oa){
    	if(!oa.statusCode){
            resp.end("<html><body><a href=\'"+
            oa.getAuthorizeTokenURI()+
            "\'>Click here to login with OAuth</a></body></html>");
        }else{
            resp.writeHead(500);
            resp.end(String(oa));
        }
    });
}

function verify(req,resp){
    var oa = getSession(req.cookies);
    var token = req.info.query.oauth_token;
    if(oa && token){
        oa.setOAuthVerifier(token);
        oa.acquireAccessToken(function(oa){
        	if(!oa.statusCode){
                resp.writeHead(302, { "Location": "/" });
                resp.end();
            }else{
                resp.writeHead(500);
                resp.end(String(oa));
            }
        });
    }else{
        resp.writeHead(302, { "Location": "/login" });
        resp.end();
    }
}

function home(req,resp){
    var oa = getSession(req.cookies);
    if(oa){
        var method = "GET";
        var uri = "http://api.fanfou.com/account/verify_credentials.json";
        var param = {};
        var header = oa.generateAuthorizationString(method,uri,param);
        var options = {
            host: 'api.fanfou.com',
            port: 80,
            path: '/account/verify_credentials.json',
            method: 'GET',
            headers:{
                'Authorization':header
            },
        };

        var creq = http.request(options, function(cres) {
        	resp.writeHead(cres.statusCode, cres.headers);
            cres.setEncoding('utf8');
            cres.on('data', function (chunk) {
                resp.write(chunk);
            });
            cres.on('end',function(){
                resp.end();
            });
        });
        creq.end();
    }else{
        resp.writeHead(302, { "Location": "/login" });
        resp.end();
    }
}

function static(req,resp){
    var p = path.normalize(req.info.pathname);
    if(p=="/")p="/index.html";
    if(!(/^\/static/.test(p))){
        p = "/static" + p;
    }
    p = "."+p;
    console.info(p);
    var stat = null;
    try{
    	stat = fs.statSync(p);
    }catch(e){}
    if(!stat || !stat.isFile()){
        resp.writeHead(404);
        resp.end("<html><body><h1>?_? Not found</h1></body></html>");
        return;
    }
    resp.writeHead(200,{'Content-Length':stat.size,'Content-Type':mime.mime_type(p)});
    var s = fs.createReadStream(p);
    s.on("end", function() {
        resp.end();
    });
    s.on("error", function(e) {
    	console.info(e);
        resp.end();
    });
    s.pipe(resp);
}

http.createServer(function (request, response) {
    request.cookies = new Cookies(request,response,"balabala");
    request.info = url.parse(request.url,true);
    if(request.info.pathname=='/'){
        home(request,response);
    }else if(request.info.pathname=='/login'){
        login(request,response);
    }else if(request.info.pathname=='/verify'){
        verify(request,response);
    }else{
        static(request,response);
    }
}).listen(config.httpd.port,config.httpd.host);


console.log('Server running at %s:%d',config.httpd.host,config.httpd.port);

