DKIM-checking SMTP proxy
========================

This is an SMTP proxy checking [DKIM](https://www.rfc-editor.org/rfc/rfc6376.html) signatures of emails.
If email has a valid signature, 2yz status code is returned and emil is reinjected for delivery.
Emails which don't have a valid DKIM signature corresponding to RFC5322.From domain are rejected with 5yz status codes.
If DKIM signature checking fails due to temporary error, such as DNS resolution error, 4yz status code is returned so the sender can retry later.

Proxy does not check [DMARC](https://www.rfc-editor.org/rfc/rfc7489) policy
and does not support other email authentication mechanisms, such as [SPF](https://tools.ietf.org/html/rfc7208).
Enforced policy of requiring a valid DKIM signature is stricter than the most strict policy configurable with DMARC,
which accepts any of DKIM or SPF authentication mechanisms.
