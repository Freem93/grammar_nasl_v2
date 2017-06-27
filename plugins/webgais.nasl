#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10300);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_cve_id("CVE-1999-0176");
 script_bugtraq_id(2058);
 script_osvdb_id(236);

 script_name(english:"WebGais webgais CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/webgais");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
code execution.");
 script_set_attribute(attribute:"description", value:
"The 'webgais' CGI is installed. This CGI may let an attacker execute
arbitrary commands with the privileges of the http daemon (usually
root or nobody).");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Jul/45");
 script_set_attribute(attribute:"solution", value:"Remove this CGI.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "webmirror.nasl");
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
res = is_cgi_installed3(item:"webgais", port:port);
if(res)security_hole(port);
