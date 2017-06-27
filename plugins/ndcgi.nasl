#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/20/009)

include("compat.inc");

if (description)
{
 script_id(11730);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");

 script_cve_id("CVE-2001-0922");
 script_bugtraq_id(3583);
 script_osvdb_id(13991);

 script_name(english:"Netdynamics ndcgi.exe Previous User Session Replay");
 script_summary(english:"Checks for the ndcgi.exe file");

 script_set_attribute(attribute:"synopsis", value:"User sessions may be hijacked on the remote host.");
 script_set_attribute(attribute:"description", value:
"The file ndcgi.exe exists on this web server. Some versions of this
file are vulnerable to remote exploit.

As Nessus solely relied on the existence of the ndcgi.exe file, this
might be a false positive");
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=100681274915525&w=2");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/26");
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
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

no404 = get_kb_item("www/no404/" + port );

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/ndcgi.exe"), port:port)) {
   	if(no404 && is_cgi_installed_ka(item:string(dir, "/nessus" + rand() + ".exe"), port:port)) exit(0);
  	flag = 1;
  	directory = dir;
  	break;
  }
}

if (flag) security_hole(port);
