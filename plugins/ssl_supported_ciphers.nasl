#TRUSTED 79476a81457e9ecc127f145902bf0e37cad75c343c4e5886452164a8e5f917cc7184e734c0f22bb63dd0cacc81450897ccd9c1d42188d09f22c9abf83a9b68ff0828da91911128effb3a319fd23e06afc6bc5542508b9f9802cfb3c3a107f64eb33759c1d0dc284cd8e858ca082fba526bcbf1fb18bc9ea2126c27bce08574bf5fd591b431f2f7485a03cc577e755ec42abf6cb165cb72e5f68c47295b19894f1095c5a2887d595843cb606f463afcc9cca277413f29ee570e5aecaa573386e27ee5fa1c8f2e3af5a6838302293adf3d406b94c40c337e6e006dca0b45e3ea3a1bb2f8a5e763f133260767f8d3c53fd20237cf768fbcd967aab4d24bb7e388f07b29e74e479323a7ed29850736eda9b1b2fc24a4ebc17c8f89423f943b331d3bc1f23ea72a4ee7803d68c5faa3fffca5ca017130c7eb25d2faa7bfbe42f7a86a9c7a7af1a3da74dfac5167b6dd45abfe06f9bf3d26749cc580f043b1dfd2a56bebc31bdcb63cd5ee3c85cb04247ae07934a11cd38ff1275770754a696db9464f7c7421cd710db87d2e39306bf4dfc4c8cc3250f5db46e513ebf0be4e6eeac11b8bdd8f7e7725a41168ced89dcd1dadf8ac5c77faf3d570fd5f84979cc8f54d44a290c27b8070c8e7adbd2c315d37f530e7b43cec4226476e4822b3de0094182b5c4f38aaf7daf480c5046c3c83afa8dbaa7c27305c2abfbe0630319e0d9cba36
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21643);
  script_version("1.49");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/27");

  script_name(english:"SSL Cipher Suites Supported");
  script_summary(english:"Checks which SSL cipher suites are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts communications using SSL.");
  script_set_attribute(attribute:"description", value:
"This plugin detects which SSL ciphers are supported by the remote
service for encrypting communications.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/docs/manmaster/apps/ciphers.html");
  # https://web.archive.org/web/20060612220742/http://www.openssl.org/docs/apps/ciphers.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d537016");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  script_timeout(30 * 60);

  exit(0);
}

include("byte_func.inc");
include("acap_func.inc");
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

##
# We want to format the cipher report returned from cipher_report()
# We are simply removing the SSL version in each strength section
# @remark The param 'report' is assumed to be already formatted by 'cipher_report()'
# @param report A report from 'cipher_report()'
# @return A modified report
##
function format_cipher_report(report)
{
  local_var regex, version;

  regex = make_list("(\s)+(SSLv2)\s", "(\s)+(SSLv3)\s", "(\s)+(TLSv1)\s",
                    "(\s)+(TLSv11)\s", "(\s)+(TLSv12)\s");

  foreach version (regex)
      report = ereg_replace(pattern:version, replace:'\n', string:report);

  return report;
}

##
# Remove the cipher_report() footer. We only need one
# cipher_list_size will determine how many times we remove the footer.
# @remark The param 'report' is assumed to be already formatted by 'cipher_report()'
# @param report A report from 'cipher_report()'
# @param cipher_array_size Length of supported_ciphers array.
# @return A modified report
##
function remove_footer(report, cipher_array_size)
{
  local_var footer, tmp;

  # If the size is only 1 then we do not want to remove the footer
  if (cipher_array_size == 1 ) return report;

  footer ='
The fields above are :

  {OpenSSL ciphername}
  Kx={key exchange}
  Au={authentication}
  Enc={symmetric encryption method}
  Mac={message authentication code}
  {export flag}';

  # Remove the footer except for one hence the '-1'
  tmp = str_replace(string:report, find:footer, replace:'', count:cipher_array_size-1);

  return tmp;
}

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers, per user config.");

get_kb_item_or_exit("SSL/Supported");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# If it's encapsulated already, make sure it's a type we support.
encaps = get_kb_item("Transports/TCP/" + port);
if (encaps > ENCAPS_IP && (encaps < ENCAPS_SSLv2 || encaps > COMPAT_ENCAPS_TLSv12))
  exit(1, "Port " + port + " uses an unsupported encapsulation method.");

# Determine whether this port uses StartTLS.
starttls = get_kb_list("*/" + port + "/starttls");
starttls = (!isnull(starttls) && max_index(starttls));

# Choose which transports to test.
if (thorough_tests)
{
  supported = make_list(
    ENCAPS_SSLv2,
    ENCAPS_SSLv3,
    ENCAPS_TLSv1,
    COMPAT_ENCAPS_TLSv11,
    COMPAT_ENCAPS_TLSv12
  );
}
else
{
  supported = get_kb_list_or_exit("SSL/Transport/" + port);
}

# Determine which ciphers are supported.
supported_ciphers = make_array();

foreach encaps (supported)
{
  if (starttls && encaps != ENCAPS_TLSv1) continue;

  if (encaps == ENCAPS_SSLv2)      ssl_ver = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);

  # Iterate over each cipher.
  foreach cipher (sort(keys(ciphers)))
  {
    # Skip ciphers that we already know are supported.
    if (supported_ciphers[encaps][cipher]) continue;

    v2 = (encaps == ENCAPS_SSLv2);
    exts = exts_len = NULL;

    if (encaps == ENCAPS_SSLv2)
    {
      # Skip SSLv3+ ciphers if in SSLv2
      if (strlen(ciphers[cipher]) != 3) continue;
    }
    else
    {
      # Skip SSLv2 ciphers if in SSLv3+
      if (strlen(ciphers[cipher]) != 2) continue;

      # Some SSL implementations require a supported named curve for it
      # to return a ServerHello, so we will send EC extensions, claiming
      # to support all curves and EC point formats.
      if (encaps >= ENCAPS_TLSv1 && tls_is_ec_cipher(cipher))
      {
        exts = tls_ext_ec() + tls_ext_ec_pt_fmt();
        exts_len  = mkword(strlen(exts));
      }
    }

    if (encaps >= ENCAPS_SSLv3)
    {
      secure_renegotiation = TRUE;
    }
    else
    {
      secure_renegotiation = FALSE;
    }

    # Create a ClientHello record.
    helo = client_hello(
      version    : ssl_ver,
      cipherspec : ciphers[cipher],
      cspeclen   : mkword(strlen(ciphers[cipher])),
      v2hello    : v2,
      extensions :exts,
      extensionslen:exts_len,
      securerenegotiation:secure_renegotiation
    );

    # Connect to the port, issuing the StartTLS command if necessary.
    soc = open_sock_ssl(port);
    if (!soc)
      exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

    # Send the ClientHello record.
    send(socket:soc, data:helo);
    recs = recv_ssl(socket:soc);
    close(soc);

    # Find and parse the ServerHello record.
    if (encaps == ENCAPS_SSLv2)
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
      );
    }
    else
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
        "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );
    }

    if (isnull(rec))
        continue;

    # Ensure that the SSL version is what we expect.
    if (rec["version"] != getword(blob:ssl_ver, pos:0)) continue;

    if (encaps == ENCAPS_SSLv2)
    {
      # Old protocols return a list of ciphers, which can either be
      # a subset of the ones we sent (we only send one), or a subset
      # of the ciphers it supports. We'll be conservative and store
      # all ciphers returned.
      foreach srv_cipher (rec["cipher_specs"])
      {
        str = raw_string(
          (srv_cipher >> 16) & 0xFF,
          (srv_cipher >>  8) & 0xFF,
          (srv_cipher >>  0) & 0xFF
        );

        foreach known_cipher (keys(ciphers))
        {
          if ("SSL2_" >!< known_cipher) continue;

          if (str == ciphers[known_cipher])
          {
            supported_ciphers[encaps][known_cipher] = TRUE;
            break;
          }
        }
      }
    }
    else
    {
      # Newer protocols only select a single cipher, which will be
      # the one we sent.
      supported_ciphers[encaps][cipher] = TRUE;
    }
  }
}

supported_ciphers_size = max_index(keys(supported_ciphers));
if (supported_ciphers_size == 0)
  exit(0, "Port " + port + " does not appear to have any ciphers enabled.");

# Stash the list of supported ciphers in the KB for future use.
# Each cipher is match to the corresponding version
# Generate report for each version and its ciphers
foreach encap (sort(supported))
{
  if (isnull(supported_ciphers[encap])) continue;
  supported_ciphers_per_encap = keys(supported_ciphers[encap]);

  foreach cipher (supported_ciphers_per_encap)
  {
   set_kb_item(name:"SSL/Ciphers/" + port, value:cipher);
  }

  if (encap == ENCAPS_SSLv2)      ssl_version = "SSLv2";
  else if (encap == ENCAPS_SSLv3) ssl_version = "SSLv3";
  else if (encap == ENCAPS_TLSv1) ssl_version = "TLSv1";
  else if (encap == COMPAT_ENCAPS_TLSv11) ssl_version = "TLSv11";
  else if (encap == COMPAT_ENCAPS_TLSv12) ssl_version = "TLSv12";

  version_header = '\nSSL Version : ' + ssl_version;

  raw_report = cipher_report(supported_ciphers_per_encap);
  report = version_header + format_cipher_report(report:raw_report) + report;
}

report = remove_footer(report:report, cipher_array_size:supported_ciphers_size);

# Finish generating the report of supported /iphers.
if (isnull(report))
  exit(1, "cipher_report() returned NULL for port " + port + ".");

report =
  '\nHere is the list of SSL ciphers supported by the remote server :' +
  '\nEach group is reported per SSL Version.' +
  '\n' + report;

if (starttls)
{
  report +=
    '\nNote that this service does not encrypt traffic by default but does' +
    '\nsupport upgrading to an encrypted connection using STARTTLS.' +
    '\n';
}

security_note(port:port, extra:report);
