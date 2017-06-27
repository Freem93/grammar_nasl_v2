
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10359);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_osvdb_id(274);

 script_name(english:"Microsoft IIS ctss.idc ODBC Sample Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /scripts/tools/ctss.idc");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has an arbitrary command
execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"/scripts/tools/ctss.idc is present. Input to the 'table' parameter is
not properly sanitized. A remote attacker could exploit this to
execute arbitrary SQL commands. If xp_cmdshell is enabled, this could
result in arbitrary command execution.");
 script_set_attribute(attribute:"solution", value:"Remove this application from the server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/01");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

cgi = "/scripts/tools/ctss.idc";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);

