#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/12/19. Deprecated due to age and accuracy.

include("compat.inc");

if(description)
{
 script_id(11873);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/12/19 21:39:03 $");

 script_bugtraq_id(8791);
 script_osvdb_id(2652);

 script_name(english:"PayPal Store Front index.php page Parameter Remote File Inclusion (deprecated)");
 script_summary(english:"Checks for the presence of index.php");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using the PayPal Store Front CGI suite which is
installed. An attacker may use this flaw to inject arbitrary code in
the remote host and gain a shell with the privileges of the web
server.

The plugin was deprecated due to being old and poorly written.
Instances of the original software cannot be found and no plugins
can be used to improve the accuracy.");
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/08");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");

 exit(0);
}

exit(0, "This plugin has been deprecated.");

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
 local_var r, req;
 
 r = http_send_recv3(port:port, method:"GET", item:string(loc,"/index.php?do=ext&page=http://xxxxxxxx/file"));

 if( isnull(r))exit(1, "Null response to index.php.");
 if(egrep(pattern:".*http://xxxxxxxx/file\.php", string:r[2]))
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
