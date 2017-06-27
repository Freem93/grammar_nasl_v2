#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10304);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/11/03 14:16:37 $");

 script_cve_id("CVE-2000-0127");
 script_bugtraq_id(969);
 script_osvdb_id(240);

 script_name(english:"WebSpeed Messenger Administration Utility Unauthenticated Access");
 script_summary(english:"Checks if webspeed can be administered");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is prone to
privilege escalation attacks.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be using Webspeed, a website creation
language used with database-driven websites.

The version of Webspeed installed on the remote host allows anonymous
access to the 'WSMadmin' utility, which is used configure Webspeed. An
attacker can exploit this issue to gain control of the affected
application.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Feb/94");
 script_set_attribute(attribute:"solution", value:
"Edit the 'ubroker.properties' file and change 'AllowMsngrCmds=1' to
'AllowMsngrCmds=0'.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/02/05");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

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

cgi = "/scripts/wsisa.dll/WService=anything?WSMadmin";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);



