#!/usr/bin/env node 

var fs = require('fs');
var qs = require('querystring');
var url = require('url');
var http = require('http');
var path = require('path');
var crypto = require('crypto');

var Cookies = require('./cookies');
var OAuth = require('./oauth');
var mime = require('./mime');
var config = require('./config');

var sessions = {};
var session_seq = Math.floor(Math.random()*1000000);

function resetSessionTimeout(session){
    if(session.timeoutId){
    	clearTimeout(session.timeoutId);
    }
    session.timeoutId = setTimeout(function(){
        sessions[session.id] = null;
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
        id : sid,
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
        cReq.host = "api.fanfou.com";
        cReq.port = 80;
        cReq.headers = cReq.headers ? cReq.headers : new Object();
        cReq.body = "";
        if(cReq.oauth){
            var oa = getSession(req.cookies);
            if(!oa){
                end({error:'Not Authorized'});
                return;
            }
            var _url = "http://"+cReq.host+cReq.path;
            var param = url.parse(cReq.path,true).query;
            if(cReq.param){
            	for(k in cReq.param)
                    param[k] = cReq.param[k];
            }
            var header = oa.generateAuthorizationString(cReq.method,_url,param);
            cReq.headers['Authorization']=header;
        }

        if(cReq.method=='POST'){
            cReq.body = qs.stringify(cReq.param);
            cReq.headers['Content-Type'] = "application/x-www-form-urlencoded";
            cReq.headers['Content-Length'] = body.length;
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
                end({
                    request: cReq,
                    response: null,
                    error: e.toString(),
                });
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
    response.setHeader("Server","KumaChan4J/1.0");
    if(request.info.pathname=='/commit'){
        commit(request,response);
    }else if(request.info.pathname=='/login'){
        login(request,response);
    }else if(request.info.pathname=='/verify'){
        verify(request,response);
    }else{
        static(request,response);
    }
}).listen(config.httpd.port,config.httpd.host);


console.log('Server running at %s:%d',config.httpd.host,config.httpd.port);

