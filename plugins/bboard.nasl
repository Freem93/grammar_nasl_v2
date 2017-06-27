#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10507);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/05/25 01:37:06 $");

 script_cve_id("CVE-2000-0629");
 script_bugtraq_id(1459);
 script_osvdb_id(406);

 script_name(english:"Sun Java Web Server bboard Servlet Command Execution");
 script_summary(english:"Checks for the presence of /servlet/sunexamples.BBoardServlet");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an arbitrary command
execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'bboard' servlet is installed in
/servlet/sunexamples.BBoardServlet. This servlet comes with default
installations of Sun Java Web Server and has a well-known security
flaw that lets anyone execute arbitrary commands with the privileges
of the web server.");
 script_set_attribute(attribute:"solution", value:"Remove the affected servlet.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/10");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
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
res = is_cgi_installed3(item:"/servlet/nessus." + rand(), port:port);
if ( res ) exit(0);

res = is_cgi_installed3(item:"/servlet/sunexamples.BBoardServlet", port:port);
if( res ) security_hole(port);

