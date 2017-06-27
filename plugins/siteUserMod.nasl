#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10253);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");

 script_cve_id("CVE-2000-0117");
 script_bugtraq_id(951);
 script_osvdb_id(201);

 script_name(english:"Cobalt siteUserMod.cgi Arbitrary Password Modification");
 script_summary(english:"Checks for the presence of /.cobalt/siteUserMod/siteUserMod.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows modification
of arbitrary passwords.");
 script_set_attribute(attribute:"description", value:
"The Cobalt 'siteUserMod' CGI appears to be installed on the remote web
server. Older versions of this CGI may allow a user with Site
Administrator access to change the password of users on the system,
such as Site Administrator or regular users, or the admin (root) user.

Note that Nessus has only determined that a script with this name
exists. It has not tried to exploit the issue or determine the version
installed.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jan/420");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jan/424");
 script_set_attribute(attribute:"solution", value:"Apply the appropriate patch referenced in the vendor advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/31");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_exclude_keys("Settings/disable_cgi_scanning");

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

cgi = string("/.cobalt/siteUserMod/siteUserMod.cgi");
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);

