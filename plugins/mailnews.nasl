#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10641);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2001-0271");
 script_bugtraq_id(2391);
 script_osvdb_id(530);

 script_name(english:"MAILNEWS mailnews.cgi Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of mailnews.cgi");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a command execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"mailnews.cgi is being hosted on the remote web server. Input to the
'address' parameter is not properly sanitized. A remote attacker could
exploit this to execute arbitrary commands with the privileges of the
web server.

Please note Nessus only checked for the presence of this CGI, and did
not attempt to exploit it, so this may be a false positive.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Feb/189");
 script_set_attribute(attribute:"solution", value:"Remove this CGI from the web server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

res = is_cgi_installed3(item:"mailnews.cgi", port:port);
if(res)
 security_hole(port);
