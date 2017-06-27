#
# This script was written by Orlando Padilla <orlando.padilla@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - only attempt to login if the policy allows it (10/25/11 and 6/2015)

include("compat.inc");

if (description)
{
  script_id(11204);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/02/04 22:38:29 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(872);

  script_name(english:"Apache Tomcat Default Accounts");
  script_summary(english:"Apache Tomcat Default Accounts");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that can be accessed with
default credentials." );
  script_set_attribute(attribute:"description", value:
"This host appears to be the running the Apache Tomcat
Servlet engine with the default accounts still configured.
A potential intruder could reconfigure this service in a way
that grants system access." );
  script_set_attribute(attribute:"solution", value:
"Change the default passwords by editing the admin-users.xml file
located in the /conf/users subdirectory of the Tomcat installation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright( english:"This script is Copyright (C) 2003-2016 Digital Defense Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www");
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:8080);

if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "Tomcat" >!< banner && "Coyote" >!< banner) exit(0, "The web server listening on port "+ port +" is not Apache Tomcat");
}

if ( supplied_logins_only ) exit(0, "Policy is configured to prevent trying default user accounts");

#assert on init
flag=1;

#list of default acnts base64()'d
auth[0]='YWRtaW46dG9tY2F0\r\n\r\n';     real_auth[0]='admin:tomcat';
auth[1]='YWRtaW46YWRtaW4=\r\n\r\n';     real_auth[1]='admin:admin';
auth[2]='dG9tY2F0OnRvbWNhdA==\r\n\r\n'; real_auth[2]='tomcat:tomcat';
auth[3]='cm9vdDpyb290\r\n\r\n';         real_auth[3]='root:root';
auth[4]='cm9sZTE6cm9sZTE=\r\n\r\n';     real_auth[4]='role1:role1';
auth[5]='cm9sZTpjaGFuZ2V0aGlz\r\n\r\n'; real_auth[5]='role:changethis';
auth[6]='cm9vdDpjaGFuZ2V0aGlz\r\n\r\n'; real_auth[6]='root:changethis';
auth[7]='dG9tY2F0OmNoYW5nZXRoaXM=\r\n\r\n';     real_auth[7]='tomcat:changethis';
auth[8]='eGFtcHA6eGFtcHA=\r\n\r\n';     real_auth[8]='xampp:xampp';
auth[9]='YWRtaW46Y2hhbmdldGhpcw==\r\n\r\n';     real_auth[9]='admin:changethis';


#basereq string
basereq = http_get(item:"/admin/contextAdmin/contextList.jsp", port:port);
basereq = basereq - '\r\n\r\n';

authBasic='\r\n' + 'Authorization: Basic ';

i = 0;
found = 0;
report = '\n';

if(get_port_state(port))
{
	if(http_is_dead(port:port))exit(0);
	
	# Check that we need any authorization at all
	soc = http_open_socket(port);
	if(!soc)exit(0);
	send(socket:soc, data:http_get(item:"/admin/contextAdmin/contextList.jsp", port:port));
	rs = http_recv(socket:soc);
	
	http_close_socket(soc);
	if(!ereg(pattern:"^HTTP/1\.[0-1] 401 ", string:rs))exit(0);
	if(("<title>Context list</title>" >< rs) || ("<title>Context Admin</title>" >< rs))exit(0);
	
	
	while( auth[i] )
	{
	 soc = http_open_socket(port);
	 if(soc)
	 {
	   t0 = basereq + authBasic + auth[i];
	   send(socket:soc,data:t0);
	   rs = http_recv(socket:soc);

           if (!isnull(rs) && !egrep(pattern:"Context (list|Admin)",string:rs))
           {
	     basereq = http_get(item:"/admin/contextAdmin/contextAdmin.html", port:port);
	     basereq = basereq - '\r\n\r\n';
	     t0 = basereq + authBasic + auth[i];
	     send(socket:soc,data:t0);
	     rs = http_recv(socket:soc);
           }  
            
       	   # minor changes between versions of jakarta
	   if(!isnull(rs) && (("<title>Context list</title>" >< rs) || ("<title>Context Admin</title>" >< rs) || "<title>Admin Context</title>" >< rs))
	   { 
		found = found + 1;
		if(found == 1)
			report = '\nThe following accounts were discovered: \n\n' + real_auth[i] + '\n';
		else {
			report = report + real_auth[i] + "\n";
		}
	   }
	   http_close_socket(soc);
	   i=i+1;	   
	  }
	}
}

# should we include the plugin description?
if (found)
{
 security_hole(port:port,extra:report);
}
