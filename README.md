
# Open Windows Event Collector

**Source Initiated** log collecting from domain-joined or non-domain-joined Windows hosts.

Web Services Management Protocol Extensions for Windows Vista (MS-WSMV)

| Transport Protocol | Port | Client | Server | Condition                                    |
|:------------------:|:----:|:------:|:------:|----------------------------------------------|
| HTTP               | 5985 | Yes    | Yes    | Trusted Host *AND* Allow unencrypted traffic |
| HTTPS              | 5986 | Yes    | Yes    | Cert. CN == Hostname *OR* Trusted Host (?)   |


| Authentication Protocol | Default | Client | Server  |
|-------------------------|:-------:|:------:|:-------:|
| Negotiage (NTLMv1)      | Yes     | Yes    | Yes     |
| Basic                   | No      | No     | Yes (?) |
| CredSSP                 | No      | No (?) | Yes (?) |
| Digest                  | Yes     | No (?) | Yes (?) |
| Kerberos                | Yes     | No (?) | Yes (?) |
