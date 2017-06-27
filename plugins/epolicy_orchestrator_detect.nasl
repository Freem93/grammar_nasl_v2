#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22493);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/06/01 15:58:57 $");

  script_name(english:"ePolicy Orchestrator Detection");
  script_summary(english:"Checks for McAfee ePO");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is an ePO console.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running McAfee ePolicy Orchestrator (ePO),
a security management solution.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include ("byte_func.inc");
include ("misc_func.inc");
include ("http.inc");

if ( NASL_LEVEL < 3000 ) exit(0);

port = get_http_port(default:80);

set_byte_order (BYTE_ORDER_LITTLE_ENDIAN);

req = crap (data:"B", length:12) + crap (data:"A", length:0x3F) + raw_string (0) + crap (data:"C", length:0x100);

data = "PO" + mkdword(0x30000001) + mkdword(strlen(req)) + req;

# data = string ("POST  /spipe?Source=nessus HTTP/1.0\r\n",
#	"Content-Length: ", strlen(data), "\r\n\r\n", data);
# r = http_send_recv_buf(port:port, data:data);

r = http_send_recv3(port: port, item:"/spipe?Source=nessus", version: 10, method:"POST",
  data: data);
if (isnull(r)) exit(0);
buf = r[2];

if ( strlen(buf) == 0 ) exit(0);

for (i=0;i<strlen(buf);i++)
  buf[i] = raw_string(ord(buf[i]) ^ 0xAA);

if (buf[0] != "P" || buf[1] != "O")
  exit (0);

code = getdword (blob:buf, pos:2);
if (code != 0x30000001)
  exit (0);

if ("RequestPublicKey" >< buf && "PackageType" >< buf)
  security_note (port);
