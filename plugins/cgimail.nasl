#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(11721);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2000-0726");
 script_bugtraq_id(1623);
 script_osvdb_id(5763);

 script_name(english:"Stalkerlab Mailers CGIMail.exe Arbitrary File Retrieval");
 script_summary(english:"Checks for the cgimail.exe file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The CGI 'CgiMail.exe' exists on this web server. Some versions of this
file are vulnerable to remote exploit.

An attacker can use this flaw to gain access to confidential data or
further escalate their privileges.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Aug/418");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2016 John Lampe");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/cgimail.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   }
}

if (flag) security_note(port);
