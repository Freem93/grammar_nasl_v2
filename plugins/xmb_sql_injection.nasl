#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11587);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(7406);
 script_osvdb_id(53633);

 script_name(english:"XMB member.php Multiple Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running XMB Forum, a web forum written in PHP. 

According to its banner, this forum is vulnerable to a SQL injection
bug which may allow an attacker to steal the passwords hashes of any
user of this forum, including the forum administrator.  Once he has
the password hashes, he can easily setup a brute-force attack to crack
the users passwords and then impersonate them.  If the administrator
password is obtained, an attacker may even edit the content of this
website." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/319411" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to XMB Forum 1.8 SP1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2011/03/12 01:05:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if XMB forums is vulnerable to a sql injection attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);


if (thorough_tests) dirs = list_uniq(make_list("/xmb", "/forum", "/forums", "/board", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Look for the version number in the login script.
  r = http_send_recv3(method: "GET", item:string(dir, "/misc.php?action=login"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  if (
    # Sample banners:
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.05</font><br />
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.5 RC4: Summer Forest<br />
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 Magic Lantern Final<br></b>
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 v2b Magic Lantern Final<br></b>
    #   Powered by XMB 1.8 Partagium SP1<br />
    #   Powered by XMB 1.9 Nexus (beta)<br />
    #   Powered by XMB 1.9.1 RC1 Nexus<br />
    #   Powered by XMB 1.9.2 Nexus (pre-Alpha)<br />
    egrep(string:res, pattern:"Powered by .*XMB(<[^>]+>)* v?(0\..*|1\.([0-7]+\..*|8 Partagium<br))")
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
 }
}
