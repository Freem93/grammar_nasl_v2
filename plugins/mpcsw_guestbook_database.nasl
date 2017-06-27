#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Subject : MPCSoftWeb Guest Book vulnerabilities.
# From: drG4njubas (drG4njmail.ru)
# Date: Sun Apr 20 2003 - 08:15:51 CDT


include("compat.inc");

if(description)
{
 script_id(11590);
 script_version ("$Revision: 1.22 $");

 script_bugtraq_id(7389, 7390);
 script_osvdb_id(54146, 54147);

 script_name(english:"MPC SoftWeb Guestbook Multiple Vulnerabilities");
 script_summary(english:"Checks for mpcsoftware_guestdata.mdb");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an ASP application that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote server is running MPCSoftwebGuestbook a set of .asp
scripts to manage an online guestbook.

This release comes with a database called 'mpcsoftware_guestdata.mdb',
usually located under '/database/' that contains sensitive
information, such as the news site administrator password.

An attacker may use this flaw to gain unauthorized access to the
remote site and potentially edit it.

Note that this server is also vulnerable to a cross-site-scripting
attack, which allows an attacker to have JavaScript code executed on
the browser of other hosts." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/253" );
 script_set_attribute(attribute:"solution", value:
"Prevent the download of .mdb files from your website." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


foreach d (cgi_dirs())
{
 res = http_send_recv3(method:"GET", item:string(d, "/database/mpcsoftware_guestdata.mdb"), port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
 
 if("Standard Jet DB" >< res[2])
	{
 	 security_warning(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 exit(0);
	 }
}
