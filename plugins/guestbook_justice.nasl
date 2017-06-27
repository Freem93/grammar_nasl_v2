#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "euronymous" <just-a-user@yandex.ru>
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com
# Subject: Justice Guestbook 1.3 vulnerabilities



include("compat.inc");

if(description)
{
 script_id(11501);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-1534", "CVE-2003-1535");
 script_bugtraq_id(7233, 7234);
 script_osvdb_id(40589, 40590);

 script_name(english:"Justice Guestbook 1.3 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP script that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Justice Guestbook.

This set of CGI has two vulnerabilities :

  - It is vulnerable to cross-site scripting attacks 
    (in jgb.php3).
  - If the user requests the file cfooter.php3, he will 
    obtain the physical path of the remote CGI.
	
An attacker may use these flaws to steal the cookies of your users
or to gain better knowledge about this host." );
 script_set_attribute(attribute:"see_also", value:
"http://securityreason.com/securityalert/3347");
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79, 200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/30");
 script_cvs_date("$Date: 2016/11/11 20:19:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for the presence of cfooter.php3");
 
  script_category(ACT_GATHER_INFO);
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
if(!can_host_php(port:port)) exit(0);


gdir = make_list(cgi_dirs());

dirs = make_list("", "/guestbook");
foreach d (gdir)
{
  dirs = make_list(dirs, string(d, "/guestbook"), d);
}

foreach dir (dirs)
{
 r = http_send_recv3(method: "GET", item:string(dir, "/cfooter.php3"), port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:"getsets().*cfooter\.php3", string:r[2]))
 	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
}
