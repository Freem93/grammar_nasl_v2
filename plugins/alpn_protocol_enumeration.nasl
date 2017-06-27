#TRUSTED 90dbc93d550f5a6daf7de6245adfdbcb56d1984fa34aab329831cb8bcfdbf70f18a4c5ba9f8dd7070d6a24f12bbf32be9bd6acd8de663d3f5c70fe5f3fa53d67950194b84b5be6bcee46183fc2ca6d4505863f56b91e8b4e56c8494607ddfb8bfaafeaa411c880c513ca5038ecb49c7ed95be63f7611703443ee24b54783647ebb581901f4bb7f9cfa48c737c8d6b1982509df2dd31fd5fcc05fbd55ad5448392ffe40e50a960465b306747859d45ca1d98533e5dc8b20944cd8851f3c59ccf9025306800d241fa62e070b6a1ec3dbd008632d161c1dd3bec0b61f33e8737d07530618584420ac71d6afa21b1df1f60d6c0630588f5729735e84a69eb7fb960a83d75f99cf560732b5aa87e9ff5c29ff8b1e3b6b53ee3d95781ad924c29d62d3d2d5b124815a77b2f63e2ed4ebe8aa08fc6ead2f49f0c2de37b813e58873935b31c479a2b1b6fb9185c8f07ae327d10cf635922ad3acc76950edf3656ee1496a9e2f70e7cfc455ce4d42743ed6c63dafb855cefc929e976840e548c719d5570d064eab6cc6d4a5b9f269af37024031de2a48192a4d40d193c59f01fe3063e63078912bad4b1fb836e4dcd5e33f11cf8488c266ca52c33e88d3c86721e1dda512aba7ba0ea1fb9f72da2314da4adda542fdd89e1d657b248d1c3b9c82165c29c420e20e7a0ea7fc913255e1786678d1e58bff6ec2d220f0c4af59b329be96887a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84821);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/02/15");

  script_name(english:"TLS ALPN Supported Protocol Enumeration");
  script_summary(english:"Enumerates TLS ALPN supported protocols.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host supports the TLS ALPN extension.");
  script_set_attribute(attribute:"description",value:
"The remote host supports the TLS ALPN extension. This plugin
enumerates the protocols the extension supports.");
  script_set_attribute(attribute:"see_also",value:"https://tools.ietf.org/html/rfc7301");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  script_exclude_keys("global_settings/disable_ssl_cipher_neg");
  exit(0);
}

include("audit.inc");
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
include("telnet2_func.inc");
include("xmpp_func.inc");
include("rsync.inc");
include("ssl_funcs.inc");

function alpn_ext()
{
  local_var item, proto_list, proto_list_str;

  proto_list_str = '';
  proto_list = _FCT_ANON_ARGS[0];

  foreach item (proto_list)
    proto_list_str += mkbyte(strlen(item)) + item;

  return  mkword(16)  +  # extension type
          mkword(strlen(proto_list_str)+2) +
          mkword(strlen(proto_list_str)) +
          proto_list_str;
}

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");
get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);

if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
protocols = make_list("http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2",
# these are additional non-iana registered protocols that are used in mod_h2, IIS 10, or
# sent by firefox/chrome
                      "spdy/3.1", "h2-14", "h2-15", "h2-16");

cipherspec = NULL;
foreach cipher (sort(keys(ciphers)))
{
  if(strlen(ciphers[cipher]) == 2)
    cipherspec +=  ciphers[cipher];
}
cspeclen = mkword(strlen(cipherspec));

versions = get_kb_list('SSL/Transport/'+port);

tls10 = tls11 = tls12 = 0;
if(! isnull(versions))
{
 foreach encap (versions)
 {
   if (encap == ENCAPS_TLSv1)              tls10 = 1;
   else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
   else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
 }
}

if(!(tls10 || tls11 || tls12))
  exit(0, 'The SSL-based service listening on port '+port+' does not appear to support TLSv1.0 or above.');

# use latest version available
if (tls12)       version = TLS_12;
else if (tls11)  version = TLS_11;
else if (tls10)  version = TLS_10;

ver = mkword(version);

report = '';
foreach protocol (protocols)
{
  soc = open_sock_ssl(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, "SSL");
  exts = alpn_ext(make_list(protocol));

  # length of all extensions
  exts_len  = mkword(strlen(exts));

  hello = client_hello(v2hello       : FALSE,
                       version       : ver,
                       extensions    : exts,
                       extensionslen : exts_len,
                       cipherspec    : cipherspec,
                       cspeclen      : cspeclen);

  send(socket:soc, data:hello);

  hellodone = NULL;

  while(1)
  {
    recs = "";
    repeat
    {
      rec = recv_ssl(socket:soc);
      if (isnull(rec)) break;
      recs += rec;
    } until (!socket_pending(soc));

    if(!recs) break;

    info = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );

    if (!isnull(info['extension_alpn_protocol']) && info['extension_alpn_protocol'] == protocol)
    {
      set_kb_item(name:"SSL/ALPN/" + port, value:info['extension_alpn_protocol']);
      report += '\n  ' + info['extension_alpn_protocol'];
    }

    hellodone = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );
    if(hellodone) break;
  }
  close(soc);
}

if(report != '')
{
  if(report_verbosity > 0)
  {
    report = '\nALPN Supported Protocols: \n' + report + '\n';
    security_note(port:port, extra:report);
  }
  else
    security_note(port);
}
else exit(0, "No ALPN extension protocols detected on port " + port + ".");
