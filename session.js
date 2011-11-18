var crypto = require('crypto');
var sessions = {};
var session_seq = Math.floor(Math.random()*1000000);

function Session(cookies,timeout,key){
    this.cookies = cookies;
    this.timeout = timeout;
    this.key = key;
}

function resetSessionTimeout(session){
    if(session.timeoutId){
    	clearTimeout(session.timeoutId);
    }
    session.timeoutId = setTimeout(function(){
        sessions[session.id] = null;
    },session.timeout);
}

Session.prototype.clear = function(){
    var sid = this.cookies.get("session_id");
    if(sid){
        var session = sessions[sid];
        if(session){
        	sessions[sid] = null;
        	clearTimeout(session.timeoutId);
        }
    }
}

Session.prototype.get = function(key){
    var sid = this.cookies.get("session_id");
    if(sid){
        var session = sessions[sid];
        if(session){
        	resetSessionTimeout(session);
            return session.values[key];
        }
    }
    return null;
}

Session.prototype.set = function(key,val){
    var sid = this.cookies.get("session_id");
    if(sid){
        var session = sessions[sid];
        if(session){
        	resetSessionTimeout(session);
            session.values[key] = val;
            return;
        }
    }
    var hmac = crypto.createHmac("sha1", this.key);
    hmac.update(String(session_seq++));
    sid = hmac.digest('hex');
    this.cookies.set("session_id",sid);
    var session = {
        timeout : this.timeout,
        values : {},
        id : sid,
    };
    session.values[key]=val;
    sessions[sid] = session;
    resetSessionTimeout(session);
}

module.exports = Session;
