#
# This script was written by Matthew North < matthewnorth@yahoo.com >
#
# Checks to see if remote Check Point FireWall is open to Web administration.
# If it is open to web administration, then a brute-force password attack
# against the Firewall can be launch.
#
# Changes by rd: Description and usage of the http_func functions.
#

# Changes by Tenable:
# - Revised plugin title, output formatting (7/03/09)


include("compat.inc");

if(description)
{
 script_id(11518);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/12/04 16:13:29 $");
 script_name(english:"Check Point FireWall-1 Open Web Administration");

 script_set_attribute(attribute:"synopsis", value:
"The remote firewall has a remotely accessible web administration
interface." );
 script_set_attribute(attribute:"description", value:
"The remote Check Point FireWall is open to Web administration.

An attacker can use it to launch a brute-force password attack
against the firewall, and eventually take control of it." );
 script_set_attribute(attribute:"solution", value:
"Disable remote Web administration or filter packets going to this
port." );
 script_set_attribute(attribute:"risk_factor", value: "None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/04");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:checkpoint:firewall-1");
script_end_attributes();


 script_summary(english:"Determines if the remote Check Point FireWall is open to Web administration");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Matthew North");
 script_family(english:"Firewalls");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = http_get_cache(port:port, item:"/");
if (res != NULL ) {
    if("ConfigToolPassword" >< res) {
           security_note(port);
    }
}
