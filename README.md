
# Open Windows Event Collector (owinec)

**O**pen **Win**dows **E**vent **C**ollector, in short owinec, is a server application, where Windows hosts can forward
their events to. Owinec is based on **source initated** log forwarding from either domain-joined or non-domain-joined
Windows hosts.

```
Computer Configuration/Administative Templates/Windows Components/ Event Forwarding/ Configure Target Subscription Manager
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

Verify that `NT Authority\Network Service` is a member of the `Event Log Readers` group on the source computer.

# WS-MAN Protocol

## Protocol Stack

The WS-MAN protocol stack is structured as follows:

```
 +--------------+
 | +----------+ |
 | |  MS-WSMV | |
 | +----------+ |
 |    WS-MAN    |
 +--------------+
 |     SOAP     |
 | +----------+ |
 | |   NLMP   | |
 | +----------+ |
 +------+-------+
 | HTTP | HTTPS |
 +------+-------+
 |     TCP      |
 +--------------+
 |      IP      |
 +--------------+
```

* Internet Protocol (IP)
* Transmission Control Protocol (TCP)
* Hypertext Transfer Protocol (HTTP)
* Hypertext Transfer Protocol Secure (HTTPS)
* Simple Object Access Protocol (SOAP)
* NTLM Authentication Protocol (NLMP)
* Web Services Management (WS-MAN)
* WS-MAN Extensions for Windows Vista (MS-WSMV)

As transport protocol either HTTP or HTTPS may be used:

| Transport Protocol | Port | WinRM Client Support | WinRM Server Support | Condition                                    |
|--------------------|:----:|:--------------------:|:--------------------:|----------------------------------------------|
| HTTP               | 5985 | Yes                  | Yes                  | Trusted Host                                 |
| HTTPS              | 5986 | Yes                  | Yes                  | Cert. CN == Hostname *OR* Trusted Host (?)   |


As authentication protocol in SOAP all listed below can be used theoretically. In practice, Windows clients only support
`Negotiate` authentication, which in turn uses NTLMv1.

| Authentication Protocol | Allowed by Default | WinRM Client Support | WinRM Server Support  |
|-------------------------|:------------------:|:--------------------:|:---------------------:|
| Negotiate (NTLMv1)      | Yes                | Yes                  | Yes                   |
| Basic                   | No                 | No                   | Yes (?)               |
| CredSSP                 | No                 | No (?)               | Yes (?)               |
| Digest                  | Yes                | No (?)               | Yes (?)               |
| Kerberos                | Yes                | No (?)               | Yes (?)               |


## Sequence Diagram

```
 +--------+                                                      +-----------+
 | Source |                                                      | Collector |
 +--------+                                                      +-----------+
     |                                                                 |
     |        +----------------------------------------------+         |
     |        | POST /wsman/SubscriptionManager/WEC          |         |
     |--------| Authorization: Negotiate TlRMTVNT...AAAADw== |-------->|
     |        | Content-Length: 0                            |         |
     |        +----------------------------------------------+         |
     |                                                                 |
     |        +----------------------------------------------+         |
     |        | 401 Unauthorized                             |         |
     |<-------| WWW-Authenticate: Negotiate TlRMTV...AAAA==  |---------|
     |        | Content-Length: 0                            |         |
     |        +----------------------------------------------+         |
     |                                                                 |
     |        +----------------------------------------------+         |
     |        | POST /wsman/SubscriptionManager/WEC          |         |
     |        | Authorization: Negotiate TlRMTVNT...7aFDpnnX |         |
     |--------| Content-Lenght: X                            |-------->|
     |        +----------------------------------------------+         |
     |        | SOAP Envelope                                |         |
     |        +----------------------------------------------+         |
     |                                                                 |
```

1. The *source* sends a `POST` request for the URL `/wsman/SubscriptionManager/WEC` and with the `Authorization` header 
    field set to `Negotiate` followed by a **NTLMv1 NEGOTIATE_MESSAGE** (see \[MS-NLMP\] section 2.2.1.1). The payload is 
    empty.
2. The *collector* response with a `401` status code and with the `WWW-Authenticate` header field set to `Negotiate` 
    followed by a **NTLMv1 CHALLENGE_MESSAGE** (see \[MS-NLMP\] section 2.2.1.2). The payload is empty.
3. The *source* authenticates itself by sending a `POST` request for the URL `/wsman/SubscriptionManager/WEC` and with 
    the `Authorization` header field set to `Negotiate` followed by a **NTMLv1 AUTHENTICATE_MESSAGE** (see \[MS-NLMP\] 
    section 2.2.1.3). The payload contains a SOAP envelope with `Action` set to `Enumerate`.


## WinRM Implementation of Source Initiated Event Forwarding

Windows implements WS-MAM in the WinRM client and server.

```http request
POST /wsman/SubscriptionManager/WEC HTTP/1.1
Connection: Keep-Alive
Content-Type: application/soap+xml;charset=UTF-16
Authorization: Negotiate TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw==
User-Agent: Microsoft WinRM Client
Content-Length: 0
Host: collector.local:5985
```

```http response
HTTP/1.1 401 
WWW-Authenticate: Negotiate TlRMTVNTUAACAAAAHgAeADgAAAA1goriYUObmGwEm2EAAAAAAAAAAJgAmABWAAAACgC6RwAAAA9XAEkATgAtAEcAMABGADkAQgBEAEwARgBHAEwARwACAB4AVwBJAE4ALQBHADAARgA5AEIARABMAEYARwBMAEcAAQAeAFcASQBOAC0ARwAwAEYAOQBCAEQATABGAEcATABHAAQAHgBEAEUAUwBLAFQATwBQAC0ANgBFAEYARQBNAEIAQgADAB4ARABFAFMASwBUAE8AUAAtADYARQBGAEUATQBCAEIABwAIAG8+avgiBNYBAAAAAA==
Server: Microsoft-HTTPAPI/2.0
Date: Fri, 27 Mar 2020 10:32:09 GMT
Content-Length: 0
```

```http request
POST /wsman/SubscriptionManager/WEC HTTP/1.1
Connection: Keep-Alive
Content-Type: multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"
Authorization: Negotiate TlRMTVNTUAADAAAAAQABAHYAAAAAAAAAdwAAAAAAAABYAAAAAAAAAFgAAAAeAB4AWAAAABAAEAB3AAAANYqI4goAukcAAAAPmD0yQwTKWnFp1Uy4jLim4lcASQBOAC0AVAAyADEATABVAE4ANgBEAEoASwA2AAAEjYlhpb73BYOeiGamkT8s
User-Agent: Microsoft WinRM Client
Content-Length: 3476
Host: collector.local:5985
```


# References

1. [\[WS-MAN\] Web Services Management](https://www.dmtf.org/standards/ws-man), DMTF
2. [\[MS-WSMV\] Web Services Management Protocol Extensions for Windows Vista](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv), Microsoft
3. [\[MS-NLMP\] NT LAN Manager (NTML) Authentication Protocol](https://docs.microsoft.com/en-gb/openspecs/windows_protocols/ms-nlmp), Microsoft
