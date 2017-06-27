#
# This script was written by Audun Larsen <larsen@xqus.com>
#

# Changes by Tenable:
# - only attempt to login if the policy allows it (10/25/11)
# - Revised plugin title, output formatting (9/3/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - Add script_exclude_key for supplied_logins_only (6/19/2015)


include("compat.inc");

if(description)
{
 script_id(12069);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/10/09 22:45:48 $");

 script_name(english:"SMC2804WBR Router Default Password (smcadmin)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is a SMC2804WBR access point.

This host is installed with a default administrator 
password (smcadmin) which has not been modified.

An attacker may exploit this flaw to gain control over
this host using the default password." );
 script_set_attribute(attribute:"solution", value:
"Change the administrator password" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"default_account", value:"true");
script_end_attributes();

 
 script_summary(english:"Logs in with default password on SMC2804WBR");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Audun Larsen");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
if ( supplied_logins_only ) exit(0, "Policy is configured to prevent trying default user accounts");
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if("SMC2804WBR" >< res && "Please enter correct password for Administrator Access. Thank you." >< res)
 {

  host = get_host_name();
  variables = string("page=login&pws=smcadmin");
  req = string("POST /login.htm HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if("<title>LOGIN</title>" >< buf)
  {
  } else {
   security_hole(port);
   exit(0);
  } 
}

