#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70657);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/04 15:31:36 $");

  script_name(english:"SSH Algorithms and Languages Supported");
  script_summary(english:"Checks which algorithms and languages are supported");

  script_set_attribute(attribute:"synopsis", value:"An SSH server is listening on this port.");
  script_set_attribute(attribute:"description", value:
"This script detects which algorithms and languages are supported by
the remote service for encrypting communications.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

# RFC 4253, Section 7.1: Algorithm Negotiation
names = make_list(
  "kex_algorithms",
  "server_host_key_algorithms",
  "encryption_algorithms_client_to_server",
  "encryption_algorithms_server_to_client",
  "mac_algorithms_client_to_server",
  "mac_algorithms_server_to_client",
  "compression_algorithms_client_to_server",
  "compression_algorithms_server_to_client",
  "languages_client_to_server",
  "languages_server_to_client"
);

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

init();

server_version = ssh_exchange_identification();
if (!server_version) exit(1, "Failed to exchange version strings with server on port " + port + ".");

ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);

max = strlen(_server_algo);
if (max < 40) exit(1, "SSH server on " + port + " responded with too few bytes to be a valid packet.");

pos = 22;
report = "";

foreach name (names)
{
  if (pos + 4 > max) break;

  len = getdword(blob:_server_algo, pos:pos);
  pos += 4;

  if (pos + len > max)
    exit(1, "SSH server on " + port + " responded with a packet having a field length beyond the packet's end.");

  list = substr(_server_algo, pos, pos + len - 1);
  pos += len;

  if (!list) continue;

  list = split(list, sep:",", keep:FALSE);

  foreach alg (list)
    set_kb_item(name:"SSH/" + port + "/" + name, value:alg);

  report +=
    '\nThe server supports the following options for ' + name + ' : ' +
    '\n' +
    '\n  ' + join(sort(list), sep:'\n  ') +
    '\n';
}

report =
  '\nNessus negotiated the following encryption algorithm with the server : ' + _crypto_algo +
  '\n' + report;

security_note(port:port, extra:report);
