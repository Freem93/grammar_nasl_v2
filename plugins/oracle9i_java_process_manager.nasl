#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (6/10/09)


include("compat.inc");

if(description)
{
 script_id(10851);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2002-0563");
 script_bugtraq_id(4293);
 script_osvdb_id(13152);

 script_name(english:"Oracle 9iAS Java Process Manager /oprocmgr-status Anonymous Process Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the list of Java processes running on the
remote host anonymously, as well as to start and stop them." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Oracle 9iAS server. By default, accessing
the location /oprocmgr-status via HTTP lets an attacker obtain
the list of processes running on the remote host, and even to
to start or stop them." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to /oprocmgr-status in httpd.conf" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
 # http://web.archive.org/web/20030407050036/http://otn.oracle.com/deploy/security/pdf/ias_modplsql_alert.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80fe4531");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/02/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2002/02/06");
 script_cvs_date("$Date: 2017/02/23 16:41:18 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_web_cache");
 script_end_attributes();

 
 script_summary(english:"Tests for Oracle9iAS Java Process Manager");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Matt Moore");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for /oprocmgr-status

 req = http_get(item:"/oprocmgr-status", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Module Name" >< r)	
 	security_warning(port);

 }
}
