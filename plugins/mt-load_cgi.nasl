#
# This script was written by Rich Walchuck (rich.walchuck at gmail.com)
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin description (3/25/2009)

include("compat.inc");

if (description)
{
 script_id(16169);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2014/05/26 01:15:51 $");

 script_name(english:"Movable Type mt-load.cgi Privilege Escalation");
 script_summary(english:"Checks for the existence of /mt/mt-load.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting Movable Type with 'mt-load.cgi'
installed.

Failure to remove mt-load.cgi could enable someone else to create a
weblog in your Movable Type installation, and possibly gain access to
your data.");
 script_set_attribute(attribute:"solution", value:"Remove the mt-load.cgi script after installation.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Rich Walchuck");
 script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www",80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);

if(is_cgi_installed_ka(item:"/mt/mt-load.cgi",port:port))
       security_warning(port);

