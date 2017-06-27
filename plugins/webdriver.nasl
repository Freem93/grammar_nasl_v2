#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10592);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_bugtraq_id(2166);
 script_osvdb_id(489);

 script_name(english:"Informix webdriver CGI Unauthenticated Database Access");
 script_summary(english:"Checks for the presence of Webdriver");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that may fail to restrict
access to an installed database.");
 script_set_attribute(attribute:"description", value:
"The remote host may be running Informix Webdriver, a web-to-database
interface. If not configured properly, this CGI script may give an
unauthenticated attacker the ability to modify and even delete
databases on the remote host.

Nessus relied solely on the presence of this CGI; it did not try to
determine if the installed version is vulnerable to that problem.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/8");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/49");
 script_set_attribute(attribute:"solution", value:"Consult the product documentation to properly configure the script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/01/08");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
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

res = is_cgi_installed3(port:port, item:"webdriver");
if(res)security_warning(port);
