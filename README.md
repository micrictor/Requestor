# Requestor
Defensive counterpart to https://github.com/SpiderLabs/Responder. The goal of this project is to conduct defense through deception in the case of an attacker running a MDNS poisoner, such as Responder, by feeding them false credentials.

```
Usage of ./Requestor:
  -auth-method string
        Web authentication method to send the credential with. Supported: Basic, NTLM (default "basic")
  -interval int
        Interval between requests, in minutes. (default 5)
  -interval-deviation int
        Tolerable deviation from the specified interval, in seconds. (default 45)
  -query-target string
        The hostname to query with the .local TLD. (default "wpad")
  -username string
        The username for the fed credential. (default "LocalAdmin")
``` 

## Best practices
* Query target should be a realistic, but invalid hostname to send credentials to. The default is [wpad](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol), but other good values might be "mailserver" or "adfs".
* Your environment should be set up to alert defenders when an attacker tries to use the specified username. 

TODO: 
* Fire alert (webhook) when poisoning is detected
* Allow specification of the user-agent
* Utilize configuration file instead of CLI-only.