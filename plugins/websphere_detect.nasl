#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57034);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 20:40:37 $");

  script_name(english:"IBM WebSphere Application Server Detection");
  script_summary(english:"Detects the IBM WebSphere Application Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application server.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server, an application server for Java-based
web applications, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/appserv-was");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/WebSphere");
  script_require_ports("Services/www", 8880, 8881, 9100);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:FALSE);
server_name = http_server_header(port:port);

version = NULL;

##
# GIOP uses TCP as its transport protocol. GIOP can be identified by its 
# four byte magic string at the beginning of every PDU: GIOP in ASCII 
# encoding. This request will return the granular version information we 
# need for reliable version checks.
#
# 47 49 4f 50 01 00 00 00  00 00 00 e4 00 00 00 02   GIOP.... ........
# 00 00 00 06 00 00 00 a0  00 00 00 00 00 00 00 28   ........ .......(
# 49 44 4c 3a 6f 6d 67 2e  6f 72 67 2f 53 65 6e 64   IDL:omg. org/Send
# 69 6e 67 43 6f 6e 74 65  78 74 2f 43 6f 64 65 42   ingConte xt/CodeB
# 61 73 65 3a 31 2e 30 00  00 00 00 01 00 00 00 00   ase:1.0. ........
# 00 00 00 64 00 01 02 00  00 00 00 0e 31 39 32 2e   ...d.... ........
# 31 36 38 2e 30 2e 31 38  36 00 04 79 00 00 00 19   ........ ...y....
# 00 00 00 00 00 00 00 00  0a 00 00 00 00 00 00 01   ........ ........
# 00 00 00 01 00 00 00 20  00 00 00 00 00 01 00 01   .......  ........
# 00 00 00 02 05 01 00 01  00 01 00 20 00 01 01 09   ........ ... ....
# 00 00 00 01 00 01 01 00  4e 45 4f 00 00 00 00 02   ........ NEO.....
# 00 0a 00 00 00 00 00 05  01 00 00 00 00 00 00 04   ........ ........
# 49 4e 49 54 00 00 00 04  67 65 74 00 00 00 00 00   INIT.... get.....
# 00 00 00 0c 4e 61 6d 65  53 65 72 76 69 63 65 00   ....Name Service.
##

wsas_init = raw_string
(
  0x47, 0x49, 0x4f, 0x50, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0xe4, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xa0,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
  0x49, 0x44, 0x4c, 0x3a, 0x6f, 0x6d, 0x67, 0x2e,
  0x6f, 0x72, 0x67, 0x2f, 0x53, 0x65, 0x6e, 0x64,
  0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65,
  0x78, 0x74, 0x2f, 0x43, 0x6f, 0x64, 0x65, 0x42,
  0x61, 0x73, 0x65, 0x3a, 0x31, 0x2e, 0x30, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 0x02, 0x00,
  0x00, 0x00, 0x00, 0x0e, 0x31, 0x39, 0x32, 0x2e,
  0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e, 0x31, 0x38,
  0x36, 0x00, 0x04, 0x79, 0x00, 0x00, 0x00, 0x19,
  0xaf, 0xab, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x93, 0xbe, 0x05, 0x06, 0x00, 0x00, 0x00, 0x08,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x02, 0x05, 0x01, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x01, 0x09,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00,
  0x4e, 0x45, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
  0x49, 0x4e, 0x49, 0x54, 0x00, 0x00, 0x00, 0x04,
  0x67, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x0c, 0x4e, 0x61, 0x6d, 0x65,
  0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x00
);

if (!isnull(server_name))
{
  if ("WebSphere Application Server" >!< server_name)
    audit(AUDIT_WRONG_WEB_SERVER, port, 'IBM WebSphere Application Server');

  pattern = "^WebSphere Application Server/([0-9.]+)($|[^0-9.])";
  item = eregmatch(pattern:pattern, string:server_name);
  if (!isnull(item))
  {
    source = server_name;
    version = item[1];
  }
}

res = http_get_cache(port:port, item:"/", exit_on_fail:TRUE);
if (':WASRemoteRuntimeVersion="' >< res)
{
  source2 = strstr(res, "<SOAP-ENV:Header");
  source2 = source2 - strstr(source2, "</SOAP-ENV:Header>");
  line = ereg_replace(pattern:"\n", replace:"", string:source2);

  matches = eregmatch(pattern:"^.*WASRemoteRuntimeVersion=.([0-9.]+).*$", string:line);
  if (!isnull(matches))
  {
    version = matches[1];
    source = source2;
  }
}

##
# This removes the WASRemoteRuntimeVersion from the SOAP-ENV Header. 
# If the header contains JMXMessageVersion and JMXVersion it is very 
# likely a WAS host
##
else if (':JMXMessageVersion' >< res && ':JMXVersion' >< res) {}
else if (isnull(server_name)) audit(AUDIT_WRONG_WEB_SERVER, port, 'IBM WebSphere Application Server');

##
# If the http check above does not return a granular version, then it is 
# not reliable, and should send a request to the GIOP service to obtain 
# the granular version information from the GIOP service.
##
if (version !~ "^[0-9]+(\.[0-9]+){2,}")
{
  s = open_sock_tcp(9100);
  if (!s) audit(AUDIT_SOCK_FAIL, port);

  send(socket:s, data:wsas_init);
  data = recv(socket:s, length:4096);

  if (isnull(data)) audit(AUDIT_RESP_NOT, port);

  pattern = "IBM WebSphere Application Server" + "........" + "([0-9.]+)";
  item = pregmatch(pattern:pattern, string:data);
  if (!isnull(item))
  {
    source = 'GIOP service';
    version = item[1];
  }
}

if (empty_or_null(version))
   audit(AUDIT_UNKNOWN_WEB_SERVER_VER, 'IBM WebSphere Application Server', port);
else if (version !~ "^[0-9]+\.[0-9]+")
   audit(AUDIT_UNKNOWN_WEB_SERVER_VER, 'IBM WebSphere Application Server', port);

set_kb_item(name:"www/WebSphere/" + port + "/installed", value:TRUE);

##
# Some versions of WSAS do not provide anything in the server_name
# field of the http response leaving the source null. Checking to 
# see if the source is empty or null and setting the source solves
# the issue and produces the expected output in the report.
##
if (empty_or_null(source))
  source = "WebSphere Application Server/"+version;

set_kb_item(name:"www/WebSphere/"+port+"/source", value:source);
set_kb_item(name:"www/WebSphere/"+port+"/version", value:version);

report =
  '\n  Source  : ' + source +
  '\n  Version : ' + version +
  '\n';

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
