#!/bin/sh
set -eu

postconf -e 'pfxhttp_overload_restrictions=check_policy_service inet:pfxhttp:23455'
postconf -M '2526/inet=2526 inet n - n - - smtpd'
postconf -P '2526/inet/smtpd_recipient_restrictions=$pfxhttp_overload_restrictions'
postconf -P '2526/inet/smtpd_sasl_auth_enable=no'

postconf -M '2527/inet=2527 inet n - n - - smtpd'
postconf -P '2527/inet/smtpd_recipient_restrictions='
postconf -P '2527/inet/smtpd_sasl_auth_enable=yes'
postconf -P '2527/inet/smtpd_sasl_type=dovecot'
postconf -P '2527/inet/smtpd_sasl_path=inet:pfxhttp:23456'

postconf -e 'pfxhttp_access_restrictions=check_recipient_access socketmap:inet:pfxhttp:23458:access'
postconf -M '2528/inet=2528 inet n - n - - smtpd'
postconf -P '2528/inet/smtpd_recipient_restrictions=$pfxhttp_access_restrictions'
postconf -P '2528/inet/smtpd_sasl_auth_enable=no'
