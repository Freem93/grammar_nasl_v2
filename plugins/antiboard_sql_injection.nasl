#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14187);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2004-2062", "CVE-2004-2063");
 script_bugtraq_id(10821);
 script_osvdb_id(8268, 8269);
 script_xref(name:"Secunia", value:"12137");
 
 script_name(english:"AntiBoard antiboard.php Multiple Parameter SQL Injection");
 script_summary(english:"AntiBoard SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the AntiBoard bulletin board
system.  There are multiple SQL injection vulnerabilities in the
remote software that may allow an attacker to execute arbitrary SQL
commands on the remote host, and possibly bypass the authentication
mechanisms of AntiBoard. 

Note, AntiBoard is also affected by a cross-site scripting
vulnerability, however Nessus has not tested this." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/328" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/27");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir (cgi_dirs()) 
 {
  r = http_send_recv3(method:"GET",item:"/antiboard.php?thread_id='", port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  if ("SELECT * FROM antiboard_threads WHERE thread_id =" >< res )
  {	
	 security_warning(port);
	 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 	 exit(0);
  }
 }
