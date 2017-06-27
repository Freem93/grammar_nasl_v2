#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(11723);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/08/03 13:48:43 $");

 script_cve_id("CVE-2000-0401");
 script_bugtraq_id(1256);
 script_osvdb_id(11440, 11441);

 script_name(english:"PDGSoft Shopping Cart Multiple Vulnerabilities");
 script_summary(english:"Checks for PDGSoft Shopping cart executables");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The executables 'redirect.exe' and/or 'changepw.exe' exist on this web
server. Some versions of these files are vulnerable to remote exploit.

An attacker can use this hole to gain access to confidential data or
escalate their privileges on the web server.

*** As Nessus solely relied on the existence of the redirect.exe or
*** changepw.exe files, this might be a false positive.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95928319715983&w=2");
 script_set_attribute(attribute:"solution", value:"The vendor has released a patch that addresses this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); # mixed

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

if (get_kb_item("www/" + port + "/no404") ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/changepw.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   }
   if(is_cgi_installed_ka(item:string(dir, "/redirect.exe"), port:port)) {
	flag = 1;
        directory = dir;
        break;
   }
}

if (flag) security_hole(port);
