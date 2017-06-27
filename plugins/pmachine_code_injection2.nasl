#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17152);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2005-0513");
 script_bugtraq_id(12597);
 script_osvdb_id(14028);

 script_name(english:"pMachine mail_autocheck.php Arbitrary Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using the pmachine CGI suite which is installed.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/20");
 script_cvs_date("$Date: 2014/04/23 16:40:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of mail_autocheck.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
 u = string(loc, "/pm/add_ons/mail_this_entry/mail_authocheck.php?pm_path=http://xxxxxxxx./&sfx=.txt");
 r = http_send_recv3(method: "GET", port: port, item: u);
 if (isnull(r)) exit(0);
 res = r[0]+r[1]+'\r\n'+r[2];
 if(egrep(pattern:".*http://xxxxxxxx./mailserver\.txt", string:res))
 {
 	security_hole(port, extra: 
strcat('\nTry this URL :\n\n', build_url(port: port, qs: u), '\n'));
	exit(0);
 }
}



foreach dir (cgi_dirs())
{
 check(loc:dir);
}
