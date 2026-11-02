# Generic Nauthilus decisions for Postfix

An opt-in `decision` subtree on a `socket_maps.<name>` or `policy_services.<name>` request bypasses the legacy template/value-field protocol and stale response-cache fallback:

```yaml
policy_services:
  domain_age:
    target: https://auth.example/api/v1/policy/decisions
    http_auth_basic: postfix-domain-age:REPLACE_ME
    decision:
      enabled: true
      namespace: mail
      action: assess-sender-domain
```

The complete subtree can be inherited from section `defaults`; an explicit entry subtree replaces it, including an explicit disable. Namespace defaults to `mail` and action to `assess-sender-domain`. Existing request HTTP authentication, OIDC, compression, deadlines and listener framing are reused. Generic mode accepts only HTTP 200, validates mandatory response status and request correlation, rejects returned obligations, and maps permit/not_applicable to DUNNO, deny to REJECT and indeterminate/malformed/network failures to DEFER_IF_PERMIT. Response text is never evaluated as a Postfix command. Redirects are disabled and decompressed replies are limited to 64 KiB. A null sender returns DUNNO.

Policy-service inputs include the envelope domain and typed SMTP client address, instance and protocol state when supplied. An optional globally unique `observation_scope` enables a hashed observation identity only at END-OF-MESSAGE with a queue ID and instance. Use action `observe-sender-domain` with the corresponding mandatory-identity schema and recording obligation. Attach it to `smtpd_end_of_data_restrictions` rather than a recipient-stage check when counting. Scope and queue/instance identity must remain stable across retries. Socketmap uses the untracked target and supplies only the sender address/domain key.

```text
smtpd_end_of_data_restrictions = check_policy_service inet:127.0.0.1:10045
# Alternative without recording or peer context:
# smtpd_sender_restrictions = check_sender_access socketmap:inet:127.0.0.1:10046:domain_age
```

Preserve independent relay restrictions. FILTER is transport routing, not an HTTP lookup. Header From is unavailable through this policy protocol; header-aware integration needs a Milter/content processor.

The external `nauthilus-domain-age-plugin` examples supply the native module, exact schemas, caller admission and reference Policy. Configure those before activating these bridge entries. Domain checks do not authenticate the claimed sender. Thresholds and unknown-data policy are operator choices.
