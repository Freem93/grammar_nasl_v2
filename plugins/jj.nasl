#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10131);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");

 script_cve_id("CVE-1999-0260");
 script_bugtraq_id(2002);
 script_osvdb_id(105);

 script_name(english:"Multiple Vendor jj CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/jj");

 script_set_attribute(attribute:"synopsis", value:"A CGI on the remote web server has a command execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'jj' CGI is installed. This CGI has a well-known security flaw
that lets a remote attacker execute arbitrary commands with the
privileges of the web server.

Please note that Nessus only checked for the existence of this CGI,
and did not attempt to exploit it.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1996/Dec/142");
 script_set_attribute(attribute:"solution", value:"Remove this CGI from the web server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1996/12/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

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

res = is_cgi_installed3(item:"jj", port:port);
if(res)security_hole(port);

