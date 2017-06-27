#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10122);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2017/03/09 14:56:42 $");

 script_cve_id("CVE-1999-0951");
 script_bugtraq_id(739);
 script_osvdb_id(3380);

 script_name(english:"OmniHTTPd imagemap.exe CGI Remote Overflow");
 script_summary(english:"Overflows /cgi-bin/imagemap.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a CGI that is affected by a remote
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'imagemap.exe' cgi is installed. This CGI is vulnerable to a
buffer overflow that will allow a remote user to execute arbitrary
commands with the privileges of your httpd server (either nobody or
root).");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Oct/235");
 script_set_attribute(attribute:"solution", value:
"Upgrade to OmniHTTPD 2.10 or later, as this reportedly fixes the
issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/10/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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

sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);

flag = 0;

foreach dir (cgi_dirs())
{
 if(is_cgi_installed3(item:string(dir, "/imagemap.exe"), port:port))
 {
  flag = 1;
  directory = dir;
  break;
 }
}

if(!flag)exit(0);

s = string(directory, "/imagemap.exe?", crap(5000));
w = http_send_recv3(method:"GET", port:port, item:s);
if (isnull(w)) security_hole(port);


