#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Should also cover BID: 3035, BID: 3050
#

include("compat.inc");

if (description)
{
 script_id(10187);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_bugtraq_id(491);
 script_osvdb_id(142, 50903, 50904, 50905);

 script_name(english:"Cognos Powerplay WE Multiple Information Disclosure Vulnerabilities");
 script_summary(english:"Checks for the ppdscgi.exe CGI");

 script_set_attribute(attribute:"synopsis", value:"A CGI is affected by information disclosure vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The CGI script ppdscgi.exe, part of the PowerPlay Web Edition package,
is installed.

Due to design problems as well as some potential web server
misconfiguration PowerPlay Web Edition may serve up data cubes in a
non-secure manner. Execution of the PowerPlay CGI pulls cube data into
files in an unprotected temporary directory.

Those files are then fed back to frames in the browser. In some cases
it is trivial for an unauthenticated user to tap into those data files
before they are purged.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=93059255403868&w=2");
 script_set_attribute(attribute:"solution", value:
"Cognos doesn't consider this problem as being an issue, so they do not
provide any solution.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/06/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
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

res = is_cgi_installed3(item:"ppdscgi.exe", port:port);
if(res)security_warning(port);
