#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (12/19/2008)

include("compat.inc");

if (description)
{
 script_id(10573);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/05/26 00:33:32 $");

 script_osvdb_id(471);

 script_name(english:"Microsoft IIS 5.0 ServerVariables_Jscript.asp Path Disclosure");
 script_summary(english:"IIS 5.0 Sample App reveals physical path of web root");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"A sample application shipped with IIS 5.0 discloses the physical path
of the web root. An attacker can use this information to make more
focused attacks.");
 script_set_attribute(attribute:"solution", value:
"Always remove sample applications from productions servers. In this
case, remove the entire /iissamples folder.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2014 Matt Moore");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_keys("Settings/ParanoidReport", "www/ASP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

res = is_cgi_installed_ka(item:"/iissamples/sdk/asp/interaction/ServerVariables_Jscript.asp", port:port);
if(res)security_warning(port);
