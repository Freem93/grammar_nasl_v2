#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10277);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");

 script_cve_id("CVE-1999-0066");
 script_bugtraq_id(719);
 script_osvdb_id(1116);

 script_name(english:"AnyForm CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of AnyForm2");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected a remote
command execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The CGI 'AnyForm2' is installed on the remote web server. Old versions
of this CGI have a well known security flaw that lets anyone execute
arbitrary commands with the privileges of the http daemon (root or
nobody).");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1995/Aug/0");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/07/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
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
res = is_cgi_installed3(item:"AnyForm2", port:port);
if( res )security_hole(port);
