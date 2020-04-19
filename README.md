
# Open Windows Event Collector (Owinec)

**O**pen **Win**dows **E**vent **C**ollector, in short Owinec, is a server application, where Windows hosts can forward
their events to. Owinec is based on **source initiated** log forwarding from either domain-joined or non-domain-joined
Windows hosts.


## Windows Configuration

Verify that `NT Authority\Network Service` is a member of the `Event Log Readers` group on the source computer.

`Computer Configuration/Administative Templates/Windows Components/Event Forwarding/Configure Target Subscription Manager`

`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`


# References

1. [\[WS-MAN\] Web Services Management](https://www.dmtf.org/standards/ws-man), DMTF
2. [\[MS-WSMV\] Web Services Management Protocol Extensions for Windows Vista](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv), Microsoft
3. [\[MS-NLMP\] NT LAN Manager (NTML) Authentication Protocol](https://docs.microsoft.com/en-gb/openspecs/windows_protocols/ms-nlmp), Microsoft
