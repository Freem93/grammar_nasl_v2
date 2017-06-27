#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(14190);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(10793);
 script_osvdb_id(53010);

 script_name(english:"PostNuke Install Script Admin Password Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application can be re-configured." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the PostNuke content management system.

The installation script of the remote PostNuke CMS (install.php) is 
accessible. An attacker may access it to reconfigure the remote PostNuke
installation and obtain the password of the remote database and PostNuke
installation." );
 script_set_attribute(attribute:"solution", value:
"Delete install.php" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();

 script_summary(english:"Determines if PostNuke's install.php is readable");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/postnuke");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


r = http_send_recv3(method: "GET", item:string(dir, "/install.php"), port:port);
if (isnull(r)) exit(0);
 
if("<title>PostNuke Installation</title>" >< r[2])
    	security_hole(port);
