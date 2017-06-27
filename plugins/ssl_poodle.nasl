#TRUSTED 356e05f7101242b6399b4dd36c1e94b144b8da7e42465af60edd6ee51d97a4be816da3b384d2ac5b9b8d9e23ae3e57a6fbd58fd89b645a2be7cee141a97920661d088d270c008f17e6c1da0f15d433050ecdf06bd510ce1ea8b8fa4ea223d6da5a8c1b807e5b94ba9fd8d6971a85e0267aa560d31cc3e1c3eaaef20a96cc57cc9b3d9e2f6d3a2a5f11a69634251bda20dd0804a42e80875edc1ffbcfb4582f4533573536a6200a566ab51ceb25703d2b34b757f7c6e8111d3a5f988dd1297c923bc553f3e1cfd13c9940d4a2a51603b4cb0aa2eb1784ebd962f6ba317f79f429682be22452e3c7084d4be7e10eea2c6be90779ae0cd3512ccc6cbf30037ef8bdbf7a1f67e85fcad9fed10b71081138592e006c175f4e97a0d42c802e20abb5591226119c5d79d7675cb7759f12f4381e3cb319622b15bd2aa437a577fb05bc27d0f47d53a4be1344486fa25134f20e455c06b30fbf2158dbe091bd9973a39fe3ed1ed91bcaf9872ce69be054794ef982f64d966c0bf993b6f8c0b70c6900a3b69f718eb17d5f42352c790e1df892d90d1ebd15f890f05b048b29f9c18de87d642ede12c83ad48ac69d6e0ab801bfa031bdba19bfb8700e3a03d17e680a4a1d457a1ec2b201ad4ce2023d26feba5fad0527a8a47af03be6516f6dffef0c922a5c211ec950e8668b9bfc8b0987ca6eb7219d5ada3da6e15f505510c693afec3ccf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78479);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/30");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)");
  script_summary(english:"Checks if SSL/TLS server supports SSLv3 and TLS Fallback SCSV.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain sensitive information from the remote host
with SSL/TLS-enabled services.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a man-in-the-middle (MitM) information
disclosure vulnerability known as POODLE. The vulnerability is due to
the way SSL 3.0 handles padding bytes when decrypting messages
encrypted using block ciphers in cipher block chaining (CBC) mode.
MitM attackers can decrypt a selected byte of a cipher text in as few
as 256 tries if they are able to force a victim application to
repeatedly send the same data over newly created SSL 3.0 connections.

As long as a client and service both support SSLv3, a connection can
be 'rolled back' to SSLv3, even if TLSv1 or newer is supported by the
client and service.

The TLS Fallback SCSV mechanism prevents 'version rollback' attacks
without impacting legacy clients; however, it can only protect
connections when the client and service support the mechanism. Sites
that cannot disable SSLv3 immediately should enable this mechanism.

This is a vulnerability in the SSLv3 specification, not in any
particular SSL implementation. Disabling SSLv3 is the only way to
completely mitigate the vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value: "https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value: "https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Disable SSLv3.

Services that must support SSLv3 should enable the TLS Fallback SCSV
mechanism until SSLv3 can be disabled.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("acap_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("rsync.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("xmpp_func.inc");
include("audit.inc");

connection_reset = FALSE;
# Send an SSLv3 ClientHello with modified cipher suite list.
# Cipher suite list must be in the format that client_hello expects.
function send_recv_client_hello(port, cipherspec)
{
  local_var soc, rec, chello;

  soc = open_sock_ssl(port);
  if (!soc) return NULL;

  chello = client_hello(
    version:mkword(SSL_V3),
    v2hello:FALSE,
    cipherspec:cipherspec
  );
  send(socket:soc, data:chello);
  rec = recv_ssl(socket:soc, partial:TRUE);
  if (socket_get_error(soc) == ECONNRESET)
    connection_reset = TRUE;
  close(soc);

  return rec;
}

function check_fallback_scsv(port, cipherspec)
{
  local_var rec, cipher_name, kb_key;

  # Add the TLS_FALLBACK_SCSV to the list
  cipherspec += raw_string(0x56, 0x00);

  rec = send_recv_client_hello(port:port, cipherspec:cipherspec);

  # If the server resets the connection, we consider the mitigation to be
  # applied. It's not technically following the spec (supposed to send an
  # alert), but functionally it's the same.
  # It appears Citrix Netscaler devices do this.
  if (connection_reset == TRUE && isnull(rec))
    return TRUE;

  rec = ssl_parse(blob:rec);
  if (isnull(rec))
    return "no-record";

  if (rec["content_type"] == SSL3_CONTENT_TYPE_ALERT &&
      rec["level"]        == SSL3_ALERT_TYPE_FATAL &&
      rec["description"]  == SSL3_ALERT_TYPE_INAPPROPRIATE_FALLBACK)
  {
    return TRUE;
  }

  # Server responded with something that's not an INAPPROPRIATE_FALLBACK alert.
  # Probably a ServerHello. If not, something is wrong so bail.
  if (rec["content_type"]   == SSL3_CONTENT_TYPE_HANDSHAKE &&
      rec["handshake_type"] == SSL3_HANDSHAKE_TYPE_SERVER_HELLO)
  {
    return FALSE;
  }

  kb_key = "ssl_poodle_fallback_scsv_test_returned";
  if (rec["content_type"] == SSL3_CONTENT_TYPE_HANDSHAKE)
    set_kb_item(name:kb_key, value:"handshake:" + rec["handshake_type"]);
  else if (rec["content_type"] == SSL3_CONTENT_TYPE_ALERT)
    set_kb_item(name:kb_key, value:"alert:" + rec["level"] + ":" + rec["description"]);
  else
    set_kb_item(name:kb_key, value:"content_type:" + rec["content_type"]);

  return "error";
}

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(0, "This host has no SSL/TLS services.");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Check if SSLv3 and if some form of TLS is supported
versions = make_list(get_kb_list_or_exit("SSL/Transport/" + port));
ssl3_supported = FALSE;
tls_supported = FALSE;
foreach version (versions)
{
  if (version == ENCAPS_SSLv3)
    ssl3_supported = TRUE;

  if (version >= ENCAPS_TLSv1)
    tls_supported = TRUE;
}
if (!ssl3_supported)
  exit(0, "The service on port " + port + " does not support SSLv3.");

cbc_supported = FALSE;
cipherspec = "";
foreach cipher_name (get_kb_list_or_exit("SSL/Ciphers/" + port))
{
  if (cipher_name !~ "^TLS1[12]?_")
    continue;

  if ("_CBC_" >!< cipher_name)
    continue;

  cbc_supported = TRUE;
  cipherspec += ciphers[cipher_name];
}

if (!cbc_supported)
  exit(0, "The service on port " + port + " supports SSLv3 but not any CBC cipher suites.");

# If the server supports only SSLv3 (nothing newer, like TLSv1.1) then
# there is no way to detect the TLS_FALLBACK_SCSV in action.
fallback_scsv_supported = FALSE;
if (tls_supported)
  fallback_scsv_supported = check_fallback_scsv(port:port, cipherspec:cipherspec);

if (fallback_scsv_supported == TRUE)
  exit(0, "The service on port " + port + " supports SSLv3 with CBC ciphers, but the Fallback SCSV mechanism is enabled.");

if (fallback_scsv_supported == "no-record")
  exit(0, "The service on port " + port + " supports SSLv3 with CBC ciphers, and the server did not reply while determining Fallback SCSV support.");

if (fallback_scsv_supported == "error")
  exit(0, "The service on port " + port + " supports SSLv3 with CBC ciphers, and support for Fallback SCSV could not be determined.");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus determined that the remote server supports SSLv3 with at least one CBC ' +
    '\n' + 'cipher suite, indicating that this server is vulnerable.\n';

  if (!tls_supported)
  {
    report +=
      '\n' + 'It appears that TLSv1 or newer is not supported on the server. Mitigating this ' +
      '\n' + 'vulnerability requires SSLv3 to be disabled and TLSv1 or newer to be enabled.';
  }
  else
  {
    # We only get here if TLS is supported *and* Fallback SCSV is not enabled.
    report +=
      '\n' + 'It appears that TLSv1 or newer is supported on the server. However, the ' +
      '\n' + 'Fallback SCSV mechanism is not supported, allowing connections to be "rolled ' +
      '\n' + 'back" to SSLv3.';
  }

  report += '\n';
}
set_kb_item(name:"SSL/vulnerable_to_poodle/"+port, value:TRUE);
security_warning(port:port, extra:report);
