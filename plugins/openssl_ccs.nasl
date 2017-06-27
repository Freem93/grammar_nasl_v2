#TRUSTED 8f6fc336e8848553abf2816da2a29aaaf0503411a0e5c3c606c625e41b06a66b1d4cf3266e7da88282124fde3450bb18bcfcf61be6b2751f41941b83fef0515f0eeb7c335feee060c59074e48ca5cec49492c3add59f47ec7cf5c13f242edd5a3b294492018ec50c77910fe70bd519900950f842a9af71df83034658302d2ef11a84013091d4b3ec5e3c87bd0291f619474fa5a93418d265868e1450098d360c88e7a0513b2dbbe963a9dfc7c151ad56de11ff1b8d3c7b833e369f33ba8ace33fcb9d9607b7edf0c2e31dd668645dec5cff6da64145c52c65041fb334fd84c9ec6aaf0d7ec3685e40cf964b951a04aa2b93865eb28d7f805df9eea28a9b71c0afd1310db3096f04984338bfa60dbd93c49ce8ad93e70e7c232820ffc331ce4a9ea23a3c3e962c6418ea12d4f873583d0f3cf4843f205ce157e57e670efa0005b7ce47440ea2d1b34658622037edbcfe87a8832d8041eee7ec244ddaad87801ac97b5ecb86e2f6f2f9fe4bad92486b0017084c645611edfc8e308dd2b6933af61ceb554f08a5adad14331fb7b49759fe8f834168f2d6481f2d47d9095a1b62dd8974053711701fa29087cb2394bfd9d8b3455e7b9bcd5c59972444a8293cc2907370eb639136fa1d7d48bfbf54e37c168c50de7cacfb65b82c75ed55d5d30030b70488572b4c54609ed52832b61e57242d3eb01be10562f82078b316e715a3aa8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74326);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/09/01");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_osvdb_id(
    104810,
    105763,
    106531,
    107729,
    107730,
    107731,
    107732
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"OpenSSL 'ChangeCipherSpec' MiTM Potential Vulnerability");
  script_summary(english:"Checks if the remote host incorrectly accepts a 'ChangeCipherSpec' message.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by a vulnerability that could
allow sensitive data to be decrypted.");
  script_set_attribute(attribute:"description", value:
"The OpenSSL service on the remote host is potentially vulnerable to a
man-in-the-middle (MiTM) attack, based on its response to two
consecutive 'ChangeCipherSpec' messages during the incorrect phase of
an SSL/TLS handshake.

This flaw could allow a MiTM attacker to decrypt or forge SSL messages
by telling the service to begin encrypted communications before key
material has been exchanged, which causes predictable keys to be used
to secure future traffic.

OpenSSL 1.0.1 is known to be exploitable. OpenSSL 0.9.8 and 1.0.0 are
not known to be vulnerable; however, the OpenSSL team has advised that
users of these older versions upgrade as a precaution. This plugin
detects and reports all versions of OpenSSL that are potentially
exploitable.

Note that Nessus has only tested for an SSL/TLS MiTM vulnerability
(CVE-2014-0224). However, Nessus has inferred that the OpenSSL service
on the remote host is also affected by six additional vulnerabilities
that were disclosed in OpenSSL's June 5th, 2014 security advisory :

  - An error exists in the 'ssl3_read_bytes' function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    allows nonce disclosure via the 'FLUSH+RELOAD' cache
    side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that permits the execution of
    arbitrary code or allows denial of service attacks.
    Note that this issue only affects OpenSSL when used
    as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the 'do_ssl3_write' function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An error exists in the 'dtls1_get_message_fragment'
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)

OpenSSL did not release individual patches for these vulnerabilities,
instead they were all patched under a single version release. Note
that the service will remain vulnerable after patching until the
service or host is restarted.");
  # http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5709faa");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"OpenSSL 0.9.8 SSL/TLS users (client and/or server) should upgrade to
0.9.8za. OpenSSL 1.0.0 SSL/TLS users (client and/or server) should
upgrade to 1.0.0m. OpenSSL 1.0.1 SSL/TLS users (client and/or server)
should upgrade to 1.0.1h.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssl_supported_versions.nasl", "openssl_ccs_1_0_1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(443, "SSL/Supported");
  exit(0);
}

include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");
include("audit.inc");
include("dump.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( get_kb_item("SSL/Supported") )
{
 port = get_ssl_ports(fork:TRUE);
 if (isnull(port))
   exit(1, "The host does not appear to have any SSL-based services.");

 ssl3 = tls10 = tls11 = tls12 = 0;

 list = get_kb_list('SSL/Transport/'+port);
 if(! isnull(list))
 {
  list = make_list(list);
  foreach encap (list)
  {
    if      (encap == ENCAPS_SSLv3)         ssl3 = 1;
    else if (encap == ENCAPS_TLSv1)         tls10 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
  }
 }

 if(! (ssl3 || tls10 || tls11 || tls12))
   exit(0, 'The SSL-based service listening on port '+port+' does not appear to support SSLv3 or above.');

 if (tls12)       version = TLS_12;
 else if (tls11)  version = TLS_11;
 else if (tls10)  version = TLS_10;
 else if (ssl3)   version = SSL_V3;
}
else
{
 if ( ! get_port_state(443) ) exit(1, "No SSL port discovered and port 443 is closed.");
 port = 443;
 version = TLS_10;
}

if (get_kb_item("SSL/earlyccs-1.0.1/" + port) == "true")
  exit(0, "Port " + port + " has already been shown to be vulnerable to CVE-2014-0224.");

# Open port
soc = open_sock_ssl(port);
if ( ! soc ) audit(AUDIT_SSL_FAIL, "SSL", port);

ver  = mkword(version);

cipherspec = NULL;
foreach cipher (sort(keys(ciphers)))
{
  if(strlen(ciphers[cipher]) == 2)
  {
    cipherspec +=  ciphers[cipher];
  }
}
cspeclen = mkword(strlen(cipherspec));

exts = tls_ext_ec() + tls_ext_ec_pt_fmt();
exts_len  = mkword(strlen(exts));

chello = client_hello(v2hello:FALSE, version:ver,
                      cipherspec : cipherspec,
                      cspeclen   : cspeclen,
                      extensions:exts,extensionslen:exts_len
                      );

send(socket:soc, data: chello);

# Read one record at a time. Expect to see at a minimum:
# ServerHello, Certificate, and ServerHelloDone.
hello_done = FALSE;
while (!hello_done)
{
  # Receive a record from the server.
  data = recv_ssl(socket:soc);
  if (isnull(data))
  {
    close(soc);
    exit(1, 'Service on TCP port ' + port + ' did not respond to ClientHello.');
  }

  # Server Hello Done.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
  );

  if (!isnull(rec))
  {
    hello_done = TRUE;

    # Make sure we use an SSL version supported by the server
    if(rec['version'] != version && rec['version'] >= 0x0300 && rec['version'] <= 0x0303)
      version = rec['version'];

    break;
  }
}

if(! hello_done)
  exit(1, 'ServerHelloDone not received from server listening on port ' + port+'.');

# The data in a ChangeCipherSpec message is a single byte of value '1'
if (version == SSL_V3)
  ccs = ssl_mk_record(version:version, type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:mkbyte(0x01));
else
  ccs = tls_mk_record(version:version, type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:mkbyte(0x01));

send(socket:soc, data:ccs);
rec = recv_ssl(socket:soc, partial:TRUE);

# Microsoft SSL services will close the connection with a TCP RST
if (isnull(rec) && socket_get_error(soc) == ECONNRESET)
  exit(0, 'The service listening on TCP port ' + port + ' closed the connection when sent an early ChangeCipherSpec message, which suggests it is not vulnerable.');

# If we got something back, it might be an alert or it might be garbage
if (!isnull(rec))
{
  parsed_rec = ssl_find(
    blob:rec,
    'content_type', SSL3_CONTENT_TYPE_ALERT,
    'description',  SSL3_ALERT_TYPE_UNEXPECTED_MESSAGE,
    'level',        SSL3_ALERT_TYPE_FATAL
  );

  close(soc);

  if (!isnull(parsed_rec))
    exit(0, 'The service listening on TCP port ' + port + ' returned an SSL alert when sent an early ChangeCipherSpec message, indicating it is not vulnerable.');
  else
    exit(1, 'The service listening on TCP port ' + port + ' responded to an early ChangeCipherSpec message, but not with a fatal SSL alert message.');
}

# We did not receive anything back, but the connection was not forcibly closed by the server.
# Probably vulnerable, but we want to confirm it's not a network latency issue or something.
# We try sending a second ChangeCipherSpec message - if the service processed our first one, it will have
# set up (bad) keys and will now be expecting encrypted messages. This second ChangeCipherSpec message will
# not be encrypted, so we will get an SSL3_ALERT_TYPE_DECRYPTION_FAILED alert from the server.

send(socket:soc, data:ccs);
rec = recv_ssl(socket:soc, partial:TRUE);

close(soc);

report = NULL;

# If we didn't get a reply to a second CCS, probably vulnerable, but could be caused by network outage.
if (isnull(rec))
{
  if (report_paranoia < 2)
    exit(1, "The service listening on TCP port " + port + ' did not respond to two consecutive ChangeCipherSpec messages.');

  report =
    '\nThe remote service accepted two consecutive ChangeCipherSpec messages at an incorrect point in the ' +
    '\nhandshake, without closing the connection or sending an SSL alert. This behavior indicates that the ' +
    '\nservice is vulnerable; however, this could also be the result of network interference.' +
    '\n';
}
# We got a reply to a second CCS, check if it's an SSL alert.
else
{
  # Is it a "decryption failed" alert?
  parsed_rec = ssl_find(
    blob:rec,
    'content_type', SSL3_CONTENT_TYPE_ALERT,
    'description',  SSL3_ALERT_TYPE_DECRYPTION_FAILED,
    'level',        SSL3_ALERT_TYPE_FATAL
  );

  # Is it a "bad MAC" alert?
  if (isnull(parsed_rec))
  {
    parsed_rec = ssl_find(
      blob:rec,
      'content_type', SSL3_CONTENT_TYPE_ALERT,
      'description',  SSL3_ALERT_TYPE_BAD_RECORD_MAC,
      'level',        SSL3_ALERT_TYPE_FATAL
    );
  }

  # If it's neither a "bad MAC" or "decryption failed" alert...
  if (isnull(parsed_rec))
    exit(1, 'The service listening on TCP port ' + port + ' responded to two consecutive ChangeCipherSpec messages, but not with a fatal SSL alert message.');

  report =
    '\nThe remote service accepted an SSL ChangeCipherSpec message at an incorrect point in the handshake ' +
    '\nleading to weak keys being used, and then attempted to decrypt an SSL record using those weak keys.' +
    '\nThis plugin detects unpatched OpenSSL 1.0.1, 1.0.0, and 0.9.8 services. Only 1.0.1 has been shown to ' +
    '\nbe exploitable; however, OpenSSL 1.0.0 and 0.9.8 have received similar patches and users of these ' +
    '\nversions have been advised to upgrade as a precaution.' +
    '\n';
}

if (report_verbosity == 0)
  report = NULL;

security_hole(port:port, extra: report);
