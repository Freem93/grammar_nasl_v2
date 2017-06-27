#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
    script_id(18413);
    script_version("$Revision: 1.12 $");
    script_cvs_date("$Date: 2012/08/15 21:05:11 $");
    script_cve_id("CVE-1999-0508");
    script_name(english:"Allied Telesyn Router/Switch Web Interface Default Password");
    script_summary(english:"Logs into Allied Telesyn routers and switches Web interface with default password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an account with a default password set." );
 script_set_attribute(attribute:"description", value:
"The Allied Telesyn Router/Switch has the default password set.

The attacker could use this default password to gain remote access to
your switch or router. This password could also be potentially used to
gain other sensitive information about your network from the device." );
 script_set_attribute(attribute:"solution", value:
"Connect to this Router/Switch and set a strong password." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
   script_family(english:"Web Servers");
   script_dependencies("http_version.nasl");
   script_require_ports("Services/www", 80);
   exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 1);

if (report_paranoia < 2)
{
  banner = get_http_banner (port:port, exit_on_fail: 1);
  if ("Server: ATR-HTTP-Server" >!< banner)
    exit(0, "The web server on port "+port+" is not ATR-HTTP-Server.");
}

w = http_send_recv3(method:"GET", item:"/", port:port, 
  username: "", password: "", exit_on_fail: 1);

if (w[0] !~ "^HTTP/1\.[01] +401 ")
 exit(0, build_url(port: port, qs:"/") + " is not protected.");

us = "manager"; pa = "friend";

w = http_send_recv3(method:"GET", item:"/", port:port, 
  username: us, password: pa, exit_on_fail: 1);

if (w[0] =~ "^HTTP/1\.[01] +200 ")
  if (report_verbosity <= 0)
    security_hole(port);
  else
    security_hole(port: port, extra: 
'\nThe following URIs will exhibit the flaw :\n\n'
+ build_url(port: port, qs:"/") + '\n'
+ build_url(port: port, qs:"/", username: us, password: pa) + '\n');

