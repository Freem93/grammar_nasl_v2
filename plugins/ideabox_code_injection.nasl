#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: Tue, 29 Apr 2003 15:06:43 +0400 (MSD)
# From: "euronymous" <just-a-user@yandex.ru>
# To: bugtraq@securityfocus.com
# Subject: IdeaBox: Remote Command Execution


include("compat.inc");

if(description)
{
 script_id(11557);
 script_version ("$Revision: 1.20 $");

 script_bugtraq_id(7488);

 script_name(english:"IdeaBox include.php ideaDir Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP script that is affected by a
remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted
on a third-party server using ideabox.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/367" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/29");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Injects a path");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(loc)
{
 local_var res;
 res = http_send_recv3(method:"GET", item:string(loc,"/include.php?ideaDir=http://xxxxxxxx"), port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if (egrep(pattern:".*http://xxxxxxxx/user\.php", string:res[2]))
 {
   security_hole(port:port);
   exit(0);
 }
}

dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
  dirs = make_list(dirs, string(d, "/ideabox"));

dirs = make_list(dirs, "", "/ideabox");



foreach dir (dirs)
{
 check(loc:dir);
}
