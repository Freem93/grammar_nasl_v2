#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(10041);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/11/17 21:12:11 $");

 script_cve_id("CVE-1999-1530", "CVE-2000-0431");
 script_bugtraq_id(777, 1238);
 script_osvdb_id(35, 1346);

 script_name(english:"Cobalt RaQ2 cgiwrap Multiple Vulnerabilities");
 script_summary(english:"Checks for the presence of /cgi-bin/cgiwrap");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host has 'cgiwrap' is installed. If you are running an
unpatched Cobalt RaQ, the version of cgiwrap distributed with that
system has a known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

This flaw exists only on the Cobalt modified cgiwrap. Standard builds
of cgiwrap are not affected.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Nov/122");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Nov/98");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/May/264");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/May/310");
 script_set_attribute(attribute:"solution", value:"Cobalt Networks has released a patch that addresses the vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2016 Mathieu Perrin");
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
res = is_cgi_installed_ka(item:"cgiwrap", port:port);
if(res)security_hole(port);


