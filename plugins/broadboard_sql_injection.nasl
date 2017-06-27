#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(14828);
 script_cve_id("CVE-2004-1555");
 script_osvdb_id(10336, 10337, 10338, 10339);
 script_xref(name:"Secunia", value:"12658");
 script_bugtraq_id(11250);
 script_version("$Revision: 1.19 $");
 script_name(english:"BroadBoard Multiple Script SQL Injection");
 script_summary(english:"SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an application written in ASP with
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running BroadBoard, an ASP script
designed to manage a web-based bulletin-board system.

There is a flaw in the remote software that could allow a remote
attacker to inject arbitrary SQL commands, which could in turn be used
to gain administrative access on the remote host." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Sep/971"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BroadBoard."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/26");
 script_cvs_date("$Date: 2017/02/23 16:41:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (! can_host_asp(port:port)) exit(0);


function check(dir)
{
  local_var buf, r;
  r = http_send_recv3(method:"GET", item:dir + "/profile.asp?handle=foo'", port:port);
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);

  if("error '80040e14'" >< buf &&
     "'tblUsers.UserHandle='foo'''" >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }
