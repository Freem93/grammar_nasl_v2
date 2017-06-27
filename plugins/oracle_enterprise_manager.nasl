#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17586);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2013/12/04 16:28:14 $");

 script_name(english:"Oracle Enterprise Manager Web Console Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is a database web management console." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to run Oracle Enterprise Manager; connections
are allowed to the web console management.

Letting attackers know that you are using this software will help them
to focus their attack or will make them change their strategy.

In addition to this, an attacker may attempt to set up a brute-force
attack to log into the remote interface." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
script_end_attributes();


 script_summary(english:"Checks for Oracle Enterprise Manager web interface");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl");

 script_require_ports(5500);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = 5500;
if(get_port_state(port))
{
 req = http_get(item:"/em/console/logon/logon", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

 if ("<title>Oracle Enterprise Manager</title>" >< rep)
 {
    security_note(port);
 }
}
