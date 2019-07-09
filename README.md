# mitm

Just a little TLS proxy for TCP connection. I created it to debug my attempt at connecting to SMTP server. So it works OK with
text line protocols (`telnet`, `openssl s_client`). The goal is just to be able to see what passes through the encrypted TLS
connection.  
It generates self signed certificates automatically for the remote you passed as `-connect`. Therefore the software you test should be
able to connect even if the certificate doesn't have any trusted CA in the system. As it is, the certificates are just stored in memory
after being generated.  

# Quick start

```
mitm -listen "127.0.0.1:9999" -connect "mail.remoteserver.com:465"
```
And then run your software on `127.0.0.1:9999`.
It should be able to accept non valid certificate.

That's it, there are no *longer detailed start*.
