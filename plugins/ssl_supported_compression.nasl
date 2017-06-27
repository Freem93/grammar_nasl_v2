#TRUSTED 35b6f08d9d75b67e036ff21b6fd0f4e62b8f72690c4053221c0b3662bba22934d29d926036e1d0261f7dfab42dae1b68bb4414b716d0438b570c9f6f0780fa8cf7353df19966a03c88e6e934c34b8613d7b78f8b45b1256b5e814c4146c4c0e937f0d14817e28afd4f3d084930e9df53d2c7f218c7e21207d44de1223c929d3b03c5f50a064ac64028f3ab23403a9ba8ba49374384ec6408e6d6b478636e7e36ff96a5e97140653436be19aeb5eb8d2517a759451d3ca866026a97d85c34eb00c0698e12c80532f1a03a49f97a89f17a864a535f703f59aeee3ed70123a9d45d9fd08ead6a009f4b72596ce227d0824354e9f896edd302b29678c7998d7c67fa0ba0a4c08e210387fc0d47b24eb6066d0805c44699322f4208849427679341da44f65e421649eeb4d939badbeae981cbf2c45c32132a70a61e276bfa0d12943a5e25d1a065d8f5ed6e82eb5e7b57f298900b756c4992c7615da4d24a9650d3031667b3f0cb613fbd2a657c4c0a696afe16dc3f9935af35e44c776bd86ff06da3caceb36f25897ed6a67d551f48cf9ac52b8e3b81daaae318a7ab7533351e9fd832a6ce7b673f3a995703639f934c0195a75b5ed903466d55ac405fcc6dc904ba05a34df22430bb8ce761eb944805e340426530b2d589cee173b0fa757ebcc5bac9b18ccf6a8276da9027bc97b9b80271d712b3d7f536d9c40d3a21f73c645a0f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62563);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/05/06");

  script_name(english:"SSL Compression Methods Supported");
  script_summary(english:"Checks which SSL compression methods are supported");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports one or more compression methods for SSL
connections.");
  script_set_attribute(attribute:"description", value:
"This script detects which compression methods are supported by the
remote service for SSL connections.");

  script_set_attribute(attribute:"see_also", value:"http://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xml");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3749");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3943");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc5246");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
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

get_kb_item_or_exit("SSL/Supported");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_SOCK_FAIL, port);

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
  versions = make_list(
    ENCAPS_SSLv2,
    ENCAPS_SSLv3,
    ENCAPS_TLSv1,
    COMPAT_ENCAPS_TLSv11,
    COMPAT_ENCAPS_TLSv12
  );
}
else
{
  versions = get_kb_list_or_exit("SSL/Transport/" + port);
}

# Determine which compressors are supported.
supported = make_array();
foreach encaps (versions)
{
  if (starttls_svc && encaps != ENCAPS_TLSv1) continue;

  if (encaps == ENCAPS_SSLv2) continue;
  else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);

  # Iterate over each possible compressor.
  for (id = 1; id < 256; id++)
  {
    # Only test known compressors unless we're being thorough.
    if (!thorough_tests && isnull(compressors[id])) continue;

    # Skip compressors that we already know are supported.
    if (supported[id]) continue;

    # Note that we must always send the NULL (0x00) compressor.
    cmps = raw_string(id);
    if (id != 0x00)
      cmps += raw_string(0x00);

    # Create a ClientHello record.
    helo = client_hello(
      version   : ssl_ver,
      compmeths : cmps,
      v2hello   : FALSE
    );

    # Connect to the port, issuing the StartTLS command if necessary.
    soc = open_sock_ssl(port);
    if (!soc)
      audit(AUDIT_SOCK_FAIL, port);

    # Send the ClientHello record.
    send(socket:soc, data:helo);
    recs = recv_ssl(socket:soc);
    close(soc);

    # Find and parse the ServerHello record.
    rec = ssl_find(
      blob:recs,
      "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
      "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );
    if (isnull(rec)) continue;

    # Ensure that the SSL version is what we expect.
    if (rec["version"] != getword(blob:ssl_ver, pos:0)) continue;

    # Ensure that the compression method matches what we sent.
    if (rec["compression_method"] != id) continue;

    supported[id] = TRUE;
  }
}

supported = keys(supported);
if (max_index(supported) == 0)
  exit(0, "Port " + port + " does not appear to have any compressors enabled.");

# Stash the list of supported compressors in the KB for future use, and convert
# to integers.
for (i = 0; i < max_index(supported); i++)
{
  id = int(supported[i]);
  supported[i] = id;
  set_kb_item(name:"SSL/Compressors/" + port, value:id);
}

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  names = make_list();
  foreach id (sort(supported))
  {
    name = compressors[id];
    if (isnull(name))
    {
      if (id <= 63)
        usage = "IETF Standards Track protocols";
      else if (id <= 223)
        usage = "non-Standards Track";
      else
        usage = "private use";

      name = "Unknown, reserved for " + usage;
    }
    name += " (" + hex(id) + ")";

    names = make_list(names, name);
  }

  if (max_index(names) == 1)
    s = " is ";
  else
    s = "s are ";

  report =
    '\nNessus was able to confirm that the following compression method' + s +
    '\nsupported by the target :' +
    '\n' +
    '\n  ' + join(names, sep:'\n  ') +
    '\n';
}

security_note(port:port, extra:report);
