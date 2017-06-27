#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10280);
 script_version ("$Revision: 1.40 $");
 script_osvdb_id(221);
 script_cvs_date("$Date: 2014/05/09 18:59:10 $");
 
 script_name(english:"Telnet Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"Telnet service appears to be running on the remote system." );
 script_set_attribute(attribute:"description", value:
"The Telnet service is running. This service is dangerous in 
the sense that it is not ciphered - that is, everyone can 
sniff the data that passes between the telnet client and 
the telnet server. This includes logins and passwords." );
 script_set_attribute(attribute:"solution", value:
"If you are running a Unix-type system, OpenSSH can be used 
instead of telnet. For Unix systems, you can comment out the 
'telnet' line in /etc/inetd.conf. For Unix systems which use 
xinetd, you will need to modify the telnet services file in the
/etc/xinetd.d folder.  After making any changes to xinetd or 
inetd configuration files, you must restart the service in order
for the changes to take affect.

In addition, many different router and switch manufacturers 
support SSH as a telnet replacement. You should contact your vendor 
for a solution which uses an encrypted session." );
 script_set_attribute(attribute:"risk_factor", value:"None" );



 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for the presence of Telnet");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");


port = get_service(svc: "telnet", default: 23, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

  r = telnet_negotiate(socket:soc);
  close(soc);
  if(r) {
    set_telnet_banner(port: port, banner: r);
    register_service(port:port, proto:"telnet");
  }

