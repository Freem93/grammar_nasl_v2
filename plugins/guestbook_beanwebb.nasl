#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "euronymous" <just-a-user@yandex.ru>
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com
# Subject: Beanwebb Guestbook v1.0 vulnerabilities



include("compat.inc");

if(description)
{
 script_id(11500);
 script_version ("$Revision: 1.24 $");
 script_bugtraq_id(7231, 7232);
 script_osvdb_id(53710, 53711);

 script_name(english:"Beanwebb's Guestbook 1.0 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Beanwebb's Guestbook. This set of CGIs has
two vulnerabilities :

  - Anyone can access the admin page (admin.php)

  - It is vulnerable to cross-site scripting attacks 
    (in add.php)

An attacker may use these flaws to steal the cookies of your users or
to inject fake information in the guestbook." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/439" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/30");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks for the presence of admin.php");
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
if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
 r = http_send_recv3(method: "GET", item:string(dir, "/admin.php"), port:port);
 if (isnull(r)) exit(0);

 if("Guestbook Admin" >< r[2] && egrep(pattern:"post.*admin\.php", string:r[2], icase:TRUE) )
 	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
}
