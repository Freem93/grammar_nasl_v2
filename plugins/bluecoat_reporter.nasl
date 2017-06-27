#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(34334);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
 script_name(english: "Blue Coat Reporter Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is used to monitor web traffic." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Blue Coat Reporter, a web reporting system
for monitoring centralized logs from Blue Coat appliances.  And this
service is used to access the application." );
 script_set_attribute(attribute:"see_also", value:"http://www.bluecoat.com/products/reporter" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Determines if the web server is from Blue Coat Reporter");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc."); 
 script_family(english: "Web Servers");
 script_dependencies("http_version.nasl");
 script_require_keys("www/BCReport");
 script_require_ports("Services/www", 8987); 
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8987);

banner = get_http_banner(port: port);
if (!banner) exit(0);
if ("BCReport/" >!< banner) exit(0);

v = eregmatch(string: banner, pattern: '(^|\n)Server:[ \t]*BCReport/([0-9.]+)');
if (isnull(v)) exit(0);

ver = v[2];

r = http_send_recv3(method:"GET", port: port, item: "/");
if (isnull(r)) exit(0);
page = strcat(r[0], r[1], '\r\n', r[2]);
if ("Blue Coat Reporter" >!< page) exit(0);

lines = egrep(string: page, pattern: "alert");
v = eregmatch(string: lines, pattern: 
'[ \t\r\n]alert[ \t]*\\([ \t]*"Blue Coat Reporter:[ \t]*([0-9.]+).*-[ \t]*build number:[ \t]*([0-9]+).*-[ \t]*UI version:[ \t]*([0-9.R]+)"');

if (! isnull(v))
{
 report = 
'\n  Version      : '+v[1]+
'\n  Build number : '+v[2]+
'\n  UI version   : '+v[3]+'\n';
 set_kb_item(name: "www/"+port+"/BCReport/Version", value: v[1]);
 set_kb_item(name: "www/"+port+"/BCReport/BuildNumber", value: v[2]);
 set_kb_item(name: "www/"+port+"/BCReport/UIVersion", value: v[3]);
}
else
{
 report = '\n  Version : '+ ver + '\n';
 set_kb_item(name: "www/"+port+"/BCReport/Version", value: ver);
}

security_note(
  port:port, 
  extra:'\nNessus collected the following information from the start page :\n'+ report
);
