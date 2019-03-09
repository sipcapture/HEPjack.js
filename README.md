<img src="https://github.com/sipcapture/homer-app/raw/master/public/img/homerseven.png" width=45 />&nbsp;<img src="https://cdn.pixabay.com/photo/2012/04/16/13/32/lock-36018_640.png" width="50"/>

# HEPject
Elegantly Sniff Forward secrecy TLS SIP to HEP at the source via Frida injected SSL library callbacks


##### Status:
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

### Todo
* More than SIP
* More than OpenSSL
* More than Words

------------

#### Made by Humans
This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons.<br>
If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest) 

###### (C) 2008-2019 QXIP BV
