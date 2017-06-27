#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10135);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/03/27 16:44:47 $");

 script_name(english:"LinuxConf Detection");
 script_summary(english:"Detects the presence of LinuxConf");

 script_set_attribute(attribute:"synopsis", value:"A LinuxConf server is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host is running LinuxConf, a web-based administration tool
for Linux. It is suggested to not allow anyone to connect to this
service.");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port, or disable this service if you
do not use it.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/03/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencies("httpver.nasl");
 script_require_ports("Services/linuxconf", 98);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:"linuxconf", default:98, exit_on_fail:TRUE);

banner = get_http_banner(port: port, exit_on_fail:TRUE);
server_response = egrep(pattern:"^Server:", string:banner, icase:TRUE);
if (!server_response) exit(0, "The web server listening on port " + port + " does not send a Server response header.");
if ("linuxconf" >!< server_response) exit(0, "The web server listening on port " + port + " is not linuxconf.");

set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

if (report_verbosity > 0)
{
  report = '\n  Source  : ' + server_response;
  version = ereg_replace(pattern:"^Server: *linuxconf/(.*)$", replace:"\1", string:server_response, icase:TRUE);
  if (version != server_replace)
  {
    response += '\n  Version : ' + version;
  }

  security_note(port:port, extra:report+'\n');
}
else security_note(port);
