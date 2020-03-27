
# Open Windows Event Collector

**Source Initiated** log collecting from domain-joined or non-domain-joined Windows hosts.


# Protocol

| Transport Protocol | Port | Source | Collector | Condition                                    |
|--------------------|:----:|:------:|:---------:|----------------------------------------------|
| HTTP               | 5985 | Yes    | Yes       | Trusted Host *AND* Allow unencrypted traffic |
| HTTPS              | 5986 | Yes    | Yes       | Cert. CN == Hostname *OR* Trusted Host (?)   |


| Authentication Protocol | Default | Source | Collector  |
|-------------------------|:-------:|:------:|:----------:|
| Negotiate (NTLMv1)      | Yes     | Yes    | Yes        |
| Basic                   | No      | No     | Yes (?)    |
| CredSSP                 | No      | No (?) | Yes (?)    |
| Digest                  | Yes     | No (?) | Yes (?)    |
| Kerberos                | Yes     | No (?) | Yes (?)    |


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

1. The *source* sends a `POST` request for the URL `/wsman/SubscriptionManager/WEC` and with the `Authorization` header field set to `Negotiate` followed by a **NTLMv1 NEGOTIATE_MESSAGE**.
    The payload is empty.
2. The *collector* response with a `401` status code and with the `WWW-Authenticate` header field set to `Negotiate` followd by a **NTLMv1 CHALLENGE_MESSAGE**.
    The payload is empty.
3. The *source* authenticates itself by sending a `POST` request for the URL `/wsman/SubscriptionManager/WEC` and with the `Authorization` header field set to `Negotiate` followed by a **NTMLv1 AUTHENTICATE_MESSAGE**
    The payload contains a SOAP envelope with `Action` set to `Enumerate`.

## Windows Implementation



# References

1. [\[WS-MAN\] Web Services Management](https://www.dmtf.org/standards/ws-man), DMTF
2. [\[MS-NLMP\] NT LAN Manager (NTML) Authentication Protocol](https://docs.microsoft.com/en-gb/openspecs/windows_protocols/ms-nlmp), Microsoft
3. [\[MS-WSMV\] Web Services Management Protocol Extensions for Windows Vista](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv), Microsoft

