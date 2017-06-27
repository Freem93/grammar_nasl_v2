#TRUSTED 2bd29ec7015ab18c9580c8e829bd8685e47b8c7d76e953205425e73da42a8e63d6035aa8f371086bfd34f3b3e33f57812e6bc93033d8caca165fc5d4f465c88b37a77e6e522b36cce045ea629345bd4956b648b9852ad4c4f67fe264f8640e4671f86db18e892ff568ed52a96913dd989e12effd7b3b3c8f8e8f2e8316cca3461864b23e89e2a885d7ebd632a7e067ef37c397bcb8b33bcad1e3e37c8e365e6170b884182f50f002e8b950da9c7ad20076c808c34e6fb35795eeb93620f7d6cb87c92e62a7782471e0f6a08acd1bf95ff517f7485eccfaf18240970951a54e5a598a59f66973facdd88f0cfd33417ec3672b2a85ca44e70a2ab98af5509460a70f7ea9536ca02eb80110988b6002aa9f2c64710696882d6f5f687e2979b7167ff7fcf52987f6ad33595efd543a235c62542fb7443304cc7d264f0c38b8462d48e8173e1c205098e20f42bf265239cb313fcad0b7a73721da9464f6dec88eeb8131409136f161e5de1779f134ca0d69b866028a3816cc4ebe9aa334679d817f5e5b39a65773699686364d407782202913ce89d2a972482d97eb06cd854173391ee34383ad52185e75c621c5fbfb764e23b618121ba79431aa7cc73dd0fc48b9b87da2e4e05c50999007cad6a4068c4ccf4be1bd2dbcd5dd32071af7b925635d00988fa7c3369870d7218ae00f327e7557aef7f191c2bae9899f6a4a1d9597703e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35297);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value: "2016/12/16");

  script_name(english:"SSL Service Requests Client Certificate");
  script_summary(english:"Checks for a certificate request in a SSL Server Hello.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service requests an SSL client certificate." );
  script_set_attribute(attribute:"description", value:
"The remote service encrypts communications using SSL/TLS, requests a
client certificate, and may require a valid certificate in order to
establish a connection to the underlying service.");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "ssl_supported_versions.nasl");

  exit(0);
}

include("audit.inc");
include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
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
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

ports = get_ssl_ports(fork:FALSE);
if(isnull(ports)) ports = make_list();

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  unknown_ports = get_kb_list("Services/unknown");
  if(!isnull(unknown_ports))
    ports = make_list(ports, unknown_ports);
}

ports = add_port_in_list(list:ports, port:443);
ports = add_port_in_list(list:ports, port:1241);

ports = list_uniq(ports);
if(max_index(ports) == 0) exit(0, "No applicable listening ports found.");

port = branch(ports);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

versions = get_kb_list('SSL/Transport/'+port);

if(isnull(versions))
  versions = make_list(ENCAPS_SSLv3, ENCAPS_TLSv1, COMPAT_ENCAPS_TLSv11, COMPAT_ENCAPS_TLSv12);

report_encaps = make_list();

foreach encaps (versions)
{
  soc = open_sock_ssl(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, "SSL");

  if(encaps == ENCAPS_SSLv3)
    ssl_ver = SSL_V3;
  else if(encaps == ENCAPS_TLSv1)
    ssl_ver = TLS_10;
  else if(encaps == COMPAT_ENCAPS_TLSv11)
    ssl_ver = TLS_11;
  else if(encaps == COMPAT_ENCAPS_TLSv12)
    ssl_ver = TLS_12;
  else continue; # we don't support any other ssl version

  ssl_ver = mkword(ssl_ver);

  hellodone = NULL;
  client_cert_requested = FALSE;

  hello = client_hello(
    version    : ssl_ver,
    v2hello    : FALSE
  );
 
  send(socket:soc, data:hello);

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

    client_cert_requested = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
    );

    if(client_cert_requested) break;

    hellodone = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );

    if(hellodone) break;
  }

  close(soc);

  if(!client_cert_requested) continue;

  if (encaps == ENCAPS_SSLv3) encaps_str = 'SSLv3';
  else if (encaps == ENCAPS_TLSv1) encaps_str = 'TLSv1';
  else if (encaps == COMPAT_ENCAPS_TLSv11) encaps_str = 'TLSv11';
  else if (encaps == COMPAT_ENCAPS_TLSv12) encaps_str = 'TLSv12';

  report_encaps = make_list(report_encaps, encaps_str);
}

if(max_index(report_encaps) == 0)
  exit(0, "The service on port " + port + " does not request any SSL client certificates.");

report_str = join(report_encaps, sep:"/");

if(report_str[0] == 'S') report_str = 'An ' + report_str;
else report_str = 'A ' + report_str;

set_kb_item(name:'Services/ssl_client_cert_requested/' + port, value:report_str);
# optimization KB
replace_kb_item(name:'Services/ssl_client_cert_requested', value:TRUE);

report_str +=  ' server is listening on this port that requests a client certificate.\n';

security_report_v4(port:port, extra:'\n' + report_str, severity:SECURITY_NOTE);
