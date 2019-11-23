<img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/>

# <img src="https://cdn.pixabay.com/photo/2012/04/16/13/32/lock-36018_640.png" width="60"/>HEPjack
Elegantly Sniff Forward secrecy TLS SIP to HEP at the source via Frida injected `libssl` callbacks
```
  ["*libssl*", ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session","SSL_SESSION_get_id"]]
```

<img src="https://user-images.githubusercontent.com/1423657/69482944-e82a0900-0e21-11ea-8c17-a1f0e80a4e87.png" width=500>

Sounds interesting? Learn more about [Frida](https://www.frida.re/)

---------

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
-X     SIP X-Header extraction to correlation_id (optional)
-R     LOG Regex extraction to correlation_id (optional)
```

## Usage
```
nodejs hepjack.js -p <process> -S 127.0.0.1 -P 9060
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
