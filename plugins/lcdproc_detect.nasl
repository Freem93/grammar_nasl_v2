#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10379);
 script_version ("$Revision: 1.11 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
 name["english"] = "LCDproc Detection";
 script_name(english:name["english"]);


 script_set_attribute(attribute:"synopsis", value:
"A LCDproc server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"LCDproc is a client/server suite which contains drivers for
LCD devices.

The remote service can be used to display messages on the LCD
display attached to the remote host." );
 script_set_attribute(attribute:"solution", value:
"If you do not use the client-server abilities of this service,
filter incoming traffic to this port or configure the remote daemon
to not listen on the network interface." );
 script_set_attribute(attribute:"see_also", value:"http://lcdproc.omnipotent.net/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Detects the LCDproc service";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
  script_require_ports("Services/lcdproc", 13666);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/lcdproc");
if( ! port )port = 13666;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:'hello\r\n');
r = recv_line(socket:soc, length:4096);
if ( ! r ) exit(0);
r = chomp(r);

if ( r =~ "LCDproc [0-9.]* " )
 {
  version = ereg_replace(pattern:".*LCDproc ([0-9.]*) .*", string:r, replace:"\1");
  report = 'nLCDproc version : ' + version;
  security_note(port:port, extra:report);
  set_kb_item(name:"lcdproc/version", value:version);
 }
