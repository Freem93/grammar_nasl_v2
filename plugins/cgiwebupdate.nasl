#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(11722);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id("CVE-2001-1150");
 script_bugtraq_id(3216);
 script_osvdb_id(6140);

 script_name(english:"Trend Micro Virus Buster cgiWebupdate.exe Arbitrary File Retrieval");
 script_summary(english:"Checks for the cgiWebupdate.exe file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The CGI 'cgiWebupdate.exe' exists on this web server. Some versions of
this file are vulnerable to remote exploit.

An attacker can use this hole to gain access to confidential data or
escalate their privileges on the web server.

*** Note that Nessus solely relied on the existence of the ***
cgiWebupdate.exe file.");
 script_set_attribute(attribute:"solution", value:"Trend Micro has released a patch that addresses this issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2014 John Lampe");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
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
   if(is_cgi_installed_ka(item:string(dir, "/cgiWebupdate.exe"), port:port)) {
  	security_warning(port);
	exit(0);
	}
   }
