#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11739);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2003-1086");
 script_bugtraq_id(7919);
 script_osvdb_id(2156);

 script_name(english:"pMachine lib.inc.php pm_path Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using the pmachine CGI suite which is installed.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/15");
 script_cvs_date("$Date: 2014/04/23 16:29:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of lib.inc.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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
 local_var r, res, u;
 u = string(loc, "/lib.inc.php?pm_path=http://xxxxxxxx&sfx=.txt");
 r = http_send_recv3(method: "GET", port: port, item: u);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:".*http://xxxxxxxx//?config\.txt", string: res))
 {
 	security_hole(port, extra:
strcat('\nTry the following URL :\n\n', build_url(port: port, qs: u), '\n'));
	exit(0);
 }
}



foreach dir (cgi_dirs())
{
 check(loc:dir);
}
