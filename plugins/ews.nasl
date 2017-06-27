#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10064);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-1999-0279");
 script_bugtraq_id(2248);
 script_osvdb_id(55);

 script_name(english:"Excite for Web Server architext_query.pl Shell Metacharacter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/ews");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an arbitrary command
execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"Excite for Webservers is installed. This CGI has a well-known security
flaw that lets a remote attacker execute arbitrary commands with the
privileges of the web server.

Versions newer than 1.1. are patched.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Dec/111");
 script_set_attribute(attribute:"solution", value:"If you are running version 1.1 or older, upgrade it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/01/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/20");

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

res = is_cgi_installed3(item:"ews/ews/architext_query.pl", port:port);
if(res)security_hole(port);

