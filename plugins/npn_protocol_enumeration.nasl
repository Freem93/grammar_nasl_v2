#TRUSTED 582b84d772de04ca3c3d0ccc4365866c13219beb0e53b7d54bbb50c714c30bc23ad9a0ab7c0d9e3314913911988d1f002d937f0013dcfd8d6c8eeec74c3e3d37ccef653500b260c040e9a9c380ca21171ff6951a51d133ade6a6a9553ca71730c943e98ca4a41616acc935cc1715a79c7ed00bfa0aeb196e280708472d0c077c5392aa07a0560b3961232ab56b57bccc73f5e705ff806f79118f18f714f137c1aaf1d6115cd250375a4a4b77dbf9e86ec8662a818e157da4131e88300b3a739b19d3f17f087249d0140c59af829de6ac59fa27c31575c3727a2776bd79e4079227317f5b6f9f81fa74b038859e02a2a7519e3a2d3ba5b6d1757b501c012a5ced2a43912a0130db5d85a39674b12343e531354361e43bbe95a05e7b1f1e0e6f88f78aa4979b22f873b6a69f82e028c6222f49e664a97a8becad3dfec85df09ea63ef19a59dd843a8aad9091f22b4562a7922695e544fa766c5de33800e27710eb6758497f13e54409ffe21e42dd0596a8d3608f5473f183d90f90715cffa4bf999458381e0c0f33be34e22edda76213e829c32a45fcc62a44138f8d5c1dd425e4039c5d9cffc98772e7be441aef560847fe332e30311143c2f03b1692eac22b9b30febfea838a83f6a5185a9d969aebe06fba095d628621b8d9a8f78489527171817eafae51f4d846fcbad21bbcf278fdac4d517a4a97e8dc085656def4d0e02e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87242);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/08");

  script_name(english:"TLS NPN Supported Protocol Enumeration");
  script_summary(english:"Enumerates TLS NPN supported protocols.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host supports the TLS NPN extension.");
  script_set_attribute(attribute:"description",value:
"The remote host supports the TLS NPN (Transport Layer Security Next
Protocol Negotiation) extension. This plugin enumerates the protocols
the extension supports.");
  script_set_attribute(attribute:"see_also",value:"https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
include("ssl_funcs.inc");

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");
get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);

if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

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

report = FALSE;

soc = open_sock_ssl(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port, "SSL");
exts = mkword(13172) + mkword(0); # Extension type + empty extension data
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

  npnprotos = info['extension_next_protocol_negotiation'];
  if (!isnull(npnprotos))
  {
    foreach proto (npnprotos)
      set_kb_item(name:"SSL/NPN/" + port, value:proto);
    report = '\n  ' + join(npnprotos, sep:'\n  ');
  }

  hellodone = ssl_find(
    blob:recs,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
  );
  if(hellodone) break;
}
close(soc);


if(report)
{
  if(report_verbosity > 0)
  {
    report = '\nNPN Supported Protocols: \n' + report + '\n';
    security_note(port:port, extra:report);
  }
  else
    security_note(port);
}
else exit(0, "No NPN extension protocols detected on port " + port + ".");
