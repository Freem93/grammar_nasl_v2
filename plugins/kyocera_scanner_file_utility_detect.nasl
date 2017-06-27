#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34117);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:"Kyocera Mita Scanner File Utility Detection");
  script_summary(english:"Sends a KMS_DIRECT_DIR_LIST request to the PC");

 script_set_attribute(attribute:"synopsis", value:
"A scanning service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kyocera Mita's Scanner File Utility, an
agent that runs on Windows hosts and allows Kyocera Mita multi-
function devices to scan to a user's desktop." );
 script_set_attribute(attribute:"solution", value:
"Limit access to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 37100, 37101);

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(37100);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 37100;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read the banner.
res = recv(socket:soc, length:6, min:4);
if (
  strlen(res) != 4 ||
  'OK\x00\x05' != res
) exit(0);


# Sends a KMS_DIRECT_DIR_LIST request to the PC and verify the response.
dir = "C:\\";
req = mkword(0x3801) + mkword(4) + dir;
req = mkword(strlen(req)) + req;

send(socket:soc, data:req);
res = recv(socket:soc, length:2, min:2);
if (strlen(res) < 2) exit(0);

len = getword(blob:res, pos:0);
res = recv(socket:soc, length:len, min:len);
close(soc);
if (strlen(res) < len) exit(0);

code = getword(blob:res, pos:0);
if (code != 0x3811) exit(0);


# Extract the directory list.
info = "";
num = getdword(blob:res, pos:4);
pos = 8;

for (i=0; i<num; i++)
{
  l = ord(res[pos]);
  s = substr(res, pos+1, pos+l);

  info += '  - ' + s + '\n';
  pos += l+1;
}


# Register and report the service.
register_service(port:port, proto:"kyocera_nscatcom");

if (report_verbosity && info)
{
  report = string(
    "\n",
    "By sending a KMS_DIRECT_DIR_LIST request, Nessus was able to obtain\n",
    "the following list of directories under ", dir, " on the remote host :\n",
    "\n",
    info
  );
  security_note(port:port, extra:report);
}
else security_note(port);
