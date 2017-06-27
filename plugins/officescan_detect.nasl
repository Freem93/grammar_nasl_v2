#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20109);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2012/03/30 23:52:34 $");


  script_name(english:"Trend Micro OfficeScan Client Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an antivirus." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TrendMicro OfficeScan client,
an embedded HTTP server used by TrendMicro Antivirus 
software." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/30");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for OfficeScan client");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_dependencie("httpver.nasl", "find_service2.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/unknown");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);

os = get_kb_item("Host/OS");
if ( os && "Windows" >!< os )exit(0);


port = get_unknown_svc();
if (!port) exit(0);
if (!get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

if(thorough_tests)
  http_set_read_timeout(3 * get_read_timeout());

req = string ("GET /?[CAVIT] Test HTTP/1.0\r\n\r\n");
r = http_send_recv_buf(port: port, data: req);
if (isnull(r)) exit(0);

if (egrep(string:r[1], pattern:"^Server: OfficeScan Client"))
{
 security_note(port:port);
 set_kb_item (name:"TrendMicro/OfficeScanClient", value:port);
}
