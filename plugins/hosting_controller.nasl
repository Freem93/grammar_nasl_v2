#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11745);
 script_bugtraq_id(3808);
 script_osvdb_id(10420, 10421, 10422, 10423, 10424);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0466");

 script_name(english:"Hosting Controller Multiple Script Arbitrary Directory Browsing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Hosting Controller application resides on this server.  
This version is vulnerable to multiple remote exploits.  

At attacker may make use of this vulnerability and use it to
gain access to confidential data and/or escalate their privileges
on the Web server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jan/39" );
 script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/05");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the vulnerable instances of Hosting Controller";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 John Lampe");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include ("global_settings.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

flag = 0;
directory = "";

file[0] = "statsbrowse.asp";
file[1] = "servubrowse.asp";
file[2] = "browsedisk.asp";
file[3] = "browsewebalizerexe.asp";
file[4] = "sqlbrowse.asp";

for (i=0; file[i]; i = i + 1) {
	foreach dir (cgi_dirs()) {
   		if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
			req = http_get(item:dir + "/" + file[i] + "?filepath=c:" + raw_string(0x5C,0x26) + "Opt=3", port:port);
			res = http_keepalive_send_recv(port:port, data:req);
			if(res == NULL) exit(0);
		       if ( (egrep(pattern:".*\.BAT.*", string:res)) || (egrep(pattern:".*\.ini.*", string:res)) ) {
					security_warning(port);
					exit(0);
				}
			}
   		}
	}
