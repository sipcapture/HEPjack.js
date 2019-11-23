/*
  Decrypts and logs a process's SSL/SIP traffic via Frida Code Injection
  2019, QXIP BV, Lorenzo Mangani <lorenzo.mangani@gmail.com>
*/

/* HEP OUT SOCKET */
var dgram = require('dgram'),
    socket = dgram.createSocket("udp4"),
    HEPjs = require('hep-js');
var parsip = require('parsip');
var hepId = 1234;
var hepPass = '';
var hepServer = '127.0.0.1';
var hepPort = 9060;
var sipOnly = false;
var xHeader = false;
var xRegex = false;
const ipInt = require('ip-to-int');

if(process.argv.indexOf("-S") != -1){ hepServer = process.argv[process.argv.indexOf("-S") + 1]; }
if(process.argv.indexOf("-P") != -1){ hepPort = process.argv[process.argv.indexOf("-P") + 1]; }
if(process.argv.indexOf("-X") != -1){ xHeader = process.argv[process.argv.indexOf("-X") + 1]; }
if(process.argv.indexOf("-R") != -1){ xRegex = process.argv[process.argv.indexOf("-R") + 1]; }

var frida = require('frida');
var fs = require('fs');
var filename = './script.js';
var fsscript;
var debug = true;
var quit = function(code,msg){
	if (msg) console.log(msg)
	process.exit(code ? code : 0);
}

if(process.argv.indexOf("-p") != -1){ var pid = process.argv[process.argv.indexOf("-p") + 1]; }
if(process.argv.indexOf("-v") != -1){ debug = true; }

if(!pid) { console.error('No process defined! Exiting'); process.exit(1); }

try {
      fs.readFile(filename, function read(err, data) {
        if (!err) {
		fsscript = data.toString();
        } else { quit(1,err); }
      });
} catch(e) { quit(1,'Failed loading Frida script!'); }

if (!pid){ process.exit(1);}

frida.attach(pid)
.then(function (session) {
  if (debug) console.log('attached:', session);
  return session.createScript(fsscript);
})
.then(function(script) {
  if(debug) { console.log('script created:', script); }
  if (!script.events){ quit(1,'failed initializing script'); }
  console.log('Press Ctrl+C to stop logging...');
  script.events.listen('message', function (message, data) {
    if(data && data.length >0) {
	if(debug) { console.log('GOT DATA:', data.toString('utf8'), message) }
	var hep_proto = { "type": "HEP", "version": 3, "payload_type": "SIP", "captureId": hepId, "capturePass": hepPass, "ip_family": 2};
	var datenow =  new Date().getTime();
	hep_proto.time_sec = Math.floor(datenow / 1000);
	hep_proto.time_usec = datenow - (hep_proto.time_sec*1000);
	hep_proto.srcIp = ipInt(message.payload.src_addr).toIP();
        hep_proto.dstIp = ipInt(message.payload.dst_addr).toIP();
        hep_proto.srcPort = message.payload.src_port;
        hep_proto.dstPort = message.payload.dst_port;
	parseSIP(data.toString('utf8'),hep_proto);
    }
  });
  script.load();
})
.catch(function (error) {
  console.log('error:', error.message);
});

/* SIP Parsing */
const parseSIP = function(msg, rcinfo){
	if (debug) console.log('Trying to parse..',msg,rcinfo);
	try {
		var sipmsg = parsip.getSIP(msg);
		if (sipmsg){
			if (sipmsg.headers['Call-ID'][0].parsed) rcinfo.correlation_id = sipmsg.headers['Call-ID'][0].parsed;
			if (xHeader) {
			  if (sipmsg.headers[xHeader][0].parsed) rcinfo.correlation_id = sipmsg.headers[xHeader][0].parsed;
			}
			sendHEP3(msg, rcinfo);
		}
	}
	catch (e) {
		if (debug) console.log(e);
		if (!sipOnly) {
			rcinfo.payload_type = 100;
			rcinfo.proto_type = 100;
			if (xRegex){
			  var extract = msg.match(xRegex);
			  if (extract && extract[1]) rcinfo.correlation_id = extract[1];
			}
			sendHEP3(msg, rcinfo);
		}
	}
}

/* HEP3 Socket OUT */
const sendHEP3 = function(msg, rcinfo){
	if (msg) {
		try {
			if (debug) console.log('Sending HEP3 Packet...');
			var hep_message = HEPjs.encapsulate(msg,rcinfo);
			if (hep_message) {
				socket = getSocket('udp4'); 
				socket.send(hep_message, 0, hep_message.length, hepPort, hepServer, function(err) {
				  	// socket.close();
				});
			}
		}
		catch (e) {
			console.log('HEP3 Error sending!');
			console.log(e);
		}
	}
}

/* UDP Socket Handler */
const getSocket = function (type) {
    if (undefined === socket) {
        socket = dgram.createSocket(type);
        socket.on('error', socketErrorHandler);
        /**
         * Handles socket's 'close' event,
         * recover socket in case of unplanned closing.
         */
        var socketCloseHandler = function () {
            if (socketUsers > 0) {
                socket = undefined;
                --socketUsers;
                getSocket(type);
            }
        };
        socket.on('close', socketCloseHandler);
    }
    return socket;
}
