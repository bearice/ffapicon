#!/usr/bin/env node 

var fs = require('fs');
var qs = require('querystring');
var url = require('url');
var http = require('http');
var path = require('path');

var Cookies = require('./cookies');
var Session = require('./session');
var OAuth = require('./oauth');
var mime = require('./mime');
var config = require('./config');

function check_session(req,resp){
	var obj = {};
    var oa = req.session.get("OAuth");
//    console.info(oa);
    if(oa && oa.user_detail){
        obj.login = true;
        obj.name  = oa.user_detail.name
    }else{
        obj.login = false;
        obj.name  = null;
    }
    resp.setHeader("Content-Type","application/json");
    resp.setHeader("Cache-Control","no-cache");
    resp.end(JSON.stringify(obj));
}

function login(req,resp){
	var oa = new OAuth(config.oauth);
    req.session.set("OAuth",oa);
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

function logout(req,resp){
    req.session.clear();
    resp.writeHead(302, { "Location": "/" });
    resp.end();
}

function verify(req,resp){
    var oa = req.session.get("OAuth");
    var token = req.info.query.oauth_verifier;
    if(oa){
        oa.setOAuthVerifier(token);
        oa.acquireAccessToken(function(oa){
        	if(!oa.statusCode){
                var header = oa.generateAuthorizationString(
                    "GET","http://"+config.server+"/account/verify_credentials.json",{}
                );
                
                var options = {
                    host: config.server,
                    port: 80,
                    path: '/account/verify_credentials.json',
                    method: 'GET',
                    headers:{
                        'Authorization'  : header
                    },
                };
                var data = "";
                http.request(options, function(res) {
                    res.setEncoding('utf8');
                    res.on('data', function (chunk) {
                        data += chunk;
                    });
                    res.on('end', function(){
                    	try{
                    		data = JSON.parse(data);
                    		oa.user_detail = data;
                    	}catch(e){
                    		console.error(e);
                        }
                        resp.writeHead(302, { "Location": "/" });
                        resp.end();
                    });
                }).end();
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

function commit(req,resp){
    function end(obj){
    	//console.info(obj);
        resp.setHeader("Content-Type","application/json");
        resp.end(JSON.stringify(obj));
    }
	if(req.method!='POST'){
        end({error:'Need POST'});
        return; 
    }
    var postData = "";
    req.setEncoding('utf8');
    req.on('data',function(data){
        postData += data;
    });
    req.on('end',function(){
        try{
            cReq = JSON.parse(postData);
        }catch(e){
            end({error:'Failed to parse JSON'});
            return;
        }
        cReq.host = config.server;
        cReq.port = 80;
        cReq.headers = cReq.headers ? cReq.headers : new Object();
        if(cReq.oauth){
            var oa = req.session.get("OAuth");
            if(!oa){
                end({error:'Not Authorized'});
                return;
            }
            var _url = "http://"+cReq.host+cReq.path;
            var param = url.parse(cReq.path,true).query;
            if(cReq.method=='POST' && cReq.body){
            	var postparam = qs.parse(cReq.body);
            	for(k in postparam)
                    param[k] = postparam[k];
            }
            var baseString = oa.debugGenerateBaseString(cReq.method,_url,param);
            cReq.headers['X-Debug-OAuth-BaseString'] = baseString;
            var header = oa.generateAuthorizationString(cReq.method,_url,param);
            cReq.headers['Authorization']=header;
        }

        if(cReq.method=='POST'){
            cReq.headers['Content-Type'] = "application/x-www-form-urlencoded";
            cReq.headers['Content-Length'] = cReq.body.length;
        }

        cReq.headers['Host'] = cReq.host;
        var options = {
        	method: cReq.method,
            host: cReq.host,
            port: cReq.port,
            path: cReq.path,
            headers: cReq.headers,
        }
        //console.info(options);
        http.request(options, function(cres) {
        	var cResp = {
                statusCode: cres.statusCode,
                status: http.STATUS_CODES[cres.statusCode],
                httpVersion: cres.httpVersion,
                headers: cres.headers,
                trialers: cres.trialers,
                body: "",
            };
            cres.setEncoding('utf8');
            cres.on('data', function (chunk) {
                cResp.body += chunk;
            });
            cres.on('error',function(e){
                end({error: e.toString()});
            });
            cres.on('end',function(){
                end({
                    request: cReq,
                    response: cResp,
                    error: null,
                });
            });
        }).end(cReq.body);
    });
}

function static(req,resp){
    var p = path.normalize(req.info.pathname);
    if(p=="/")p="/index.html";
    if(!(/^\/static/.test(p))){
        p = "/static" + p;
    }
    p = "."+p;
    //console.info(p);
    var stat = null;
    try{
    	stat = fs.statSync(p);
    }catch(e){}
    if(!stat || !stat.isFile()){
        resp.writeHead(404);
        resp.end("<html><body><h1>?_? Not found</h1></body></html>");
        return;
    }
    var mtime = req.headers['if-modified-since'];
    if(mtime){
        if(mtime == stat.mtime.toString()){
            resp.writeHead(304,{
    	        'Date'          : stat.ctime.toString(),
            	'Last-Modified' : stat.mtime.toString(),
    	        'Cache-Control' : 'max-age=31536000',
            });
            resp.end();
            return;
        }
    }
    resp.writeHead(200,{
    	'Content-Length': stat.size,
    	'Content-Type'  : mime.mime_type(p),
    	'Date'          : stat.ctime.toString(),
    	'Last-Modified' : stat.mtime.toString(),
    	'Cache-Control' : 'max-age=31536000',
    });
    if(req.head=='HEAD'){
        resp.end();
        return;
    }
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

var dispatch = {
    '/commit' : commit,
    '/login'  : login,
    '/logout' : logout,
    '/verify' : verify,
    '/check_session' : check_session,
};

http.createServer(function (request, response) {
	console.info("%s %s %s",request.connection.remoteAddress,request.method,request.url);
    request.cookies = new Cookies(request,response,config.cookies_key);
    request.session = new Session(request.cookies,config.session.timeout,config.session.key);

    request.info = url.parse(request.url,true);
    response.setHeader("Server","KumaChan4J/1.0");
    
    var handler = dispatch[request.info.pathname];
    if(handler){
        handler(request,response);
    }else{
        static(request,response);
    }
}).listen(config.httpd.port,config.httpd.host);


console.log('Server running at %s:%d',config.httpd.host,config.httpd.port);

