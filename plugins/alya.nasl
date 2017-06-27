#
# This script was written by Jason Lidow <jason@brandx.net>
#
# Changes by Tenable:
# - Overhauled description, added Synopsis/Reference/Solution (12/8/2008)

include("compat.inc");

if (description)
{
 script_id(11118);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_name(english:"alya.cgi CGI Backdoor Detection");
 script_summary(english:"Detects /cgi-bin/alya.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that indicates the
presence of a compromised system.");
 script_set_attribute(attribute:"description", value:
"alya.cgi was found on the remote system. This script is likely a CGI
based backdoor distributed with multiple rootkits.");
 script_set_attribute(attribute:"see_also", value:"http://cns.utoronto.ca/~scan/expltool.txt");
 script_set_attribute(attribute:"solution", value:
"Remove the alya.cgi script from the web server. In addition, perform a
full audit of the server to ensure no additional backdoor scripts are
present.");
 script_set_attribute(attribute:"risk_factor", value:"High");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/09/04");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2014 Jason Lidow");
 script_family(english:"Backdoors");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"alya.cgi");
if( res )security_hole(port);
