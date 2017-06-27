#
# Tenable Network Security, Inc.
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "bugtracklist.fm" <bugtracklist@freemail.hu>
# To: <bugtraq@securityfocus.com>
# Subject: TextPortal Default Password Vulnerability
# Date: Sat, 24 May 2003 00:15:52 +0200

include("compat.inc");

if (description)
{
 script_id(11660);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2013/12/23 02:27:58 $");
 script_bugtraq_id(7673);
 script_osvdb_id(4930);

 script_name(english:"TextPortal Default Passwords");
 script_summary(english:"Logs into the remote TextPortal interface");

 script_set_attribute(attribute:"synopsis", value:"Default administrator passwords have not been changed.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the TextPortal content management interface.
This set of scripts come with two default administrator passwords :

	- admin
	- 12345

At least one of these two passwords is still set. An attacker
could use them to edit the content of the remote website.");
 script_set_attribute(attribute:"solution", value:
"Edit admin_pass.php and change the passwords of these users.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/28");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only", "Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(dir, passwd, port)
{
 local_var	r;
 r = http_send_recv3(method: 'POST', item: dir + "/admin.php", port: port,
		data: "op=admin_enter&passw=" + passwd,
		add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
 if (isnull(r)) exit(0);
 if ("admin.php?blokk=" >< r[1]+r[2]) return(1);
}

port = get_http_port(default:80, php:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

passwds = make_list("admin", "12345");

if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 	if(is_cgi_installed3(port:port, item:dir + "/admin.php"))
	{
 		foreach pass (passwds)
		{
 			if(check(dir:dir, passwd:pass, port: port))
 			{
 			security_hole(port);
			exit(0);
 			}
 		}
	}
 }
}
