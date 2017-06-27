#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25656);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2017/03/03 17:26:56 $");

 script_name(english:"IBM Spectrum Protect / Tivoli Storage Manager Service Detection");
 script_summary(english:"Detects IBM Spectrum Protect / Tivoli Storage Manager.");

 script_set_attribute(attribute:"synopsis", value:
"A backup agent is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running IBM Spectrum Protect, formerly known as
Tivoli Storage Manager, a backup and data protection server.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

 script_dependencie("find_service2.nasl");
 script_require_ports("Services/unknown", 1500);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("install_func.inc");

function send_verb (socket, code, data)
{
 local_var header, req;

 header =
	mkbyte(0) +
	mkbyte(strlen(data)+4) +
	mkbyte(code) +
	mkbyte(0xa5);  # magic

 req = header + data;

 send(socket:socket, data:req);
}

function recv_verb(socket, code)
{
 local_var header, data, len;

 header = recv(socket:socket, length:4, min:4, timeout:10);
 if (isnull(header)) return NULL;

 # We expect at least 4 bytes
 if(strlen(header) < 4) return NULL;

 # checks magic byte
 if (ord(header[3]) != 0xa5) return NULL;

 # check response code
 if (ord(header[2]) != 0x1e) return NULL;

 len = ord(header[1]);
 if (len < 4) return NULL;

 len = len - 4;

 data = recv(socket:socket, length:len, min:len, timeout:10);

 return data;
}

# Check unknown services
if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1500);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (silent_service(port)) audit(AUDIT_SVC_SILENT,port);
} else port = 1500;

if (known_service(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if(!soc) audit(AUDIT_SOCK_FAIL,port);

send_verb(socket:soc, code:0x1d, data:NULL);
resp = recv_verb(socket:soc, code:0x1e);

len = strlen(resp);

# Always 41 bytes
if (len < 41) audit(AUDIT_RESP_BAD,port);

# Server Name and OS Lengths
len1 = getword(blob:resp, pos:13);
len2 = getword(blob:resp, pos:15);

# Version parts
version     = getword(blob:resp, pos:17);
release     = getword(blob:resp, pos:19);
level       = getword(blob:resp, pos:21);
sub_level   = getword(blob:resp, pos:23);
fullversion = version+"."+release+"."+level+"."+sub_level;
# Express version flag, deprecated in most newer versions
flag        = (ord(resp[29]) & 08);
app         = "IBM Tivoli Storage Manager";

# For report
isexpress = "No";
if(flag) isexpress = "Yes";

register_service(port:port, proto:"tsm-agent");

hostname = NULL;
osname   = NULL;
# Extra report information
extra    = make_array(
	'IsExpress', isexpress
);
# Boolean to check for Express
extra_no_report = make_array(
  "Express", flag
);
# As near as I can tell ONLY versions 4 and below do not
# include this information, this check is for backwards
# compatibility
if(len > 41)
{
  hostname = substr(resp, 41, 41+len1-1);
  osname   = substr(resp, 41+len1, 41+len1+len2-1);
  extra["ReportedOS"] = osname;
  extra["ServerName"] = hostname;
}

register_install(
  app_name:app,
  path:port,
  port:port,
  extra:extra,
  extra_no_report:extra_no_report,
  version:fullversion,
  cpe:'cpe:/a:ibm:tivoli_storage_manager'
);

report_installs(app_name:app, port:port);
