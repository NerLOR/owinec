
# Open Windows Event Collector

**Source Initiated** log collecting from domain-joined or non-domain-joined Windows hosts.

Web Services Management Protocol Extensions for Windows Vista (MS-WSMV)

| Transport Protocol | Port | Client | Server | Condition                                    |
|--------------------|:----:|:------:|:------:|----------------------------------------------|
| HTTP               | 5985 | Yes    | Yes    | Trusted Host *AND* Allow unencrypted traffic |
| HTTPS              | 5986 | Yes    | Yes    | Cert. CN == Hostname *OR* Trusted Host (?)   |


| Authentication Protocol | Default | Client | Server  |
|-------------------------|:-------:|:------:|:-------:|
| Negotiate (NTLMv1)      | Yes     | Yes    | Yes     |
| Basic                   | No      | No     | Yes (?) |
| CredSSP                 | No      | No (?) | Yes (?) |
| Digest                  | Yes     | No (?) | Yes (?) |
| Kerberos                | Yes     | No (?) | Yes (?) |

```
+--------+                                                      +-----------+
| Source |                                                      | Collector |
+--------+                                                      +-----------+
    |                                                                 |
    |        +----------------------------------------------+         |
    |        | NTLMv1 NEGOTIATE                             |         |
    |        +----------------------------------------------+         |
    |--------| POST /wsman/SubscriptionManager/WEC          |-------->|
    |        | Authorization: Negotiate TlRMTVNT...AAAADw== |         |
    |        | Content-Length: 0                            |         |
    |        +----------------------------------------------+         |
    |                                                                 |
    |        +----------------------------------------------+         |
    |        | NTLMv1 CHALLENGE                             |         |
    |        +----------------------------------------------+         |
    |<-------| 401 Unauthorized                             |---------|
    |        | WWW-Authenticate: Negotiate TlRMTV...AAAA==  |         |
    |        | Content-Length: 0                            |         |
    |        +----------------------------------------------+         |
    |                                                                 |
    |        +----------------------------------------------+         |
    |        | NTLMv1 AUTHENTICATE                          |         |
    |        +----------------------------------------------+         |
    |        | POST /wsman/SubscriptionManager/WEC          |         |
    |--------| Authorization: Negotiate TlRMTVNT...7aFDpnnX |-------->|
    |        | Content-Lenght: X                            |         |
    |        +----------------------------------------------+         |
    |        | SOAP Envelope                                |         |
    |        +----------------------------------------------+         |
    |                                                                 |
```

# References

1. [\[WS-MAN\] Web Services Management](https://www.dmtf.org/standards/ws-man), DMTF
2. [\[MS-NLMP\] NT LAN Manager (NTML) Authentication Protocol](https://docs.microsoft.com/en-gb/openspecs/windows_protocols/ms-nlmp), Microsoft
3. [\[MS-WSMV\] Web Services Management Protocol Extensions for Windows Vista](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv), Microsoft

