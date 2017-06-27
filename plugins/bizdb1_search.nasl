#
# Locate /cgi-bin/bizdb1-search.cgi
#
# This plugin was written in NASL by RWT roelof@sensepost.com 26/4/2000
# Regards,
# Roelof@sensepost.com

include("compat.inc");

if (description)
{
 script_id(10383);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2000-0287");
 script_bugtraq_id(1104);
 script_osvdb_id(291);

 script_name(english:"BizDB bizdb-search.cgi Arbitrary Command Execution");
 script_summary(english:"Determines the presence of cgi-bin/bizdb1-search.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application with a remote command
execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"BizDB is a web database integration product using Perl CGI scripts.
One of the scripts, bizdb-search.cgi, passes a variable's contents to
an unchecked open() call and can therefore be made to execute commands
at the privilege level of the web server.

The variable is dbname, and if passed a semicolon followed by shell
commands they will be executed. This cannot be exploited from a
browser, as the software checks for a referrer field in the HTTP
request. A valid referrer field can however be created and sent
programmatically or via a network utility like netcat.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/47");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of the software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/04/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Roelof Temmingh <roelof@sensepost.com>");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
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

cgi = string("bizdb1-search.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if( res ) {
	if ( is_cgi_installed_ka(item:"nessus" + rand() + ".cgi", port:port) ) exit(0);
	security_hole(port);
}
