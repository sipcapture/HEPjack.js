<img src="https://cdn.pixabay.com/photo/2012/04/16/13/32/lock-36018_640.png" width="50"/>

# HEPject
Elegantly Sniff SSL/TLS SIP to HEP via Frida Injection

Status:
* Experimental! Please test & contribute!

## Requirements
* NodeJS 10.x
* Frida 
   * ```sudo pip install frida```

## Installation
```
npm install
```

### Parameters
```
-p     pid or process to attach to
-S     HEP Server IP/hostname
-P     HEP Server port
```

## Usage
```
nodejs hepject.js -p <process> -S 127.0.0.1 -P 9060
```

