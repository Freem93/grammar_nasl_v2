#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16456);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/08/09 00:11:21 $");

 script_cve_id("CVE-2005-0436", "CVE-2005-0437", "CVE-2005-0438");
 script_bugtraq_id(12545, 12543, 12572);
 script_osvdb_id(13832, 13833, 13834);

 script_name(english:"AWStats Multiple Remote Vulnerabilities (Cmd Exec, Traversal, ID)");
 script_summary(english:"Determines the presence of debug output in AWStats");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is affected by multiple
issues.");
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free logfile analysis tool for
analyzing ftp, mail, web, ...  traffic.

The remote version of this software is prone to a command execution flaw
as well as an information disclosure vulnerability.  An attacker may
exploit this feature to obtain more information about the setup of the
remote host or to execute arbitrary commands with the privileges of the
web server.");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("awstats_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/AWStats");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

global_var port;

function check(url)
{
 local_var r, res;

 r = http_send_recv3(method:"GET", item:url +"/awstats.pl?debug=2", port:port);
 if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond.");
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ( "DEBUG 2 - PluginMode=" >< res )
 {
        security_hole(port);
        exit(0);
 }
}

port = get_http_port(default:80, embedded: 0);


install = get_install_from_kb(appname:'AWStats', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/AWStats' KB item is missing.");
dir = install['dir'];

check(url:dir);
