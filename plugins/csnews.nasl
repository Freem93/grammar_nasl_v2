#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/15/009)

include("compat.inc");

if (description)
{
 script_id(11726);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2002-0923");
 script_bugtraq_id(4994);
 script_osvdb_id(8134);

 script_name(english:"CGIScript.net csNews.cgi Advanced Settings Multiple Parameter Arbitrary File Retrieval");
 script_summary(english:"Checks for the csnews.cgi file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The CSNews.cgi exists on this web server. Some versions of this file
are vulnerable to remote exploit. An attacker can submit a specially
crafted web form, which can display the 'setup.cgi' file that contains
the superuser name and password.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/97");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 John Lampe");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);
if ( ! banner || "Server: Microsoft/IIS" >!< banner ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/csNews.cgi"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   }
}

if (flag) security_hole(port);
