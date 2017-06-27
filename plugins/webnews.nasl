#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/13/2009)

include("compat.inc");

if (description)
{
 script_id(11732);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_cve_id("CVE-2002-0290");
 script_bugtraq_id(4124);
 script_osvdb_id(5335);

 script_name(english:"Netwin WebNews Webnews.exe Remote Overflow");
 script_summary(english:"Checks for the Webnews.exe file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running WebNews, which offers web-based
access to Usenet news.

Some versions of WebNews are prone to a buffer overflow when
processing a query string with an overly-long group parameter. An
attacker may be able to leverage this issue to execute arbitrary shell
code on the remote host subject to the permissions of the web server
user id.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Feb/250");
 script_set_attribute(attribute:"solution", value:
"Apply the patch made released by the vendor on February 14th, 2002 if
running Webnews 1.1 or older.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
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
   if(is_cgi_installed_ka(item:string(dir, "/Webnews.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   }
}

if (flag) security_warning(port);
