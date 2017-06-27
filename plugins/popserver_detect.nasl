#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10185);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
 name["english"] = "POP Server Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A POP server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a server that understands the Post Office
Protocol (POP), used by email clients to retrieve messages from a
server, possibly across a network link." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Post_Office_Protocol" );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "POP Server Detection";;
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl");
 script_require_ports("Services/pop3", 110);
 
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/pop3");
if ( ! port ) port = 110;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

line = recv_line(socket:soc, length:4096);

if ( line =~ "\+OK " )
{
 send(socket:soc, data:'LIST\r\n');
 r = recv_line(socket:soc, length:1024);
 if ( r =~ "\+OK " ) exit(0); # Apop ?
 send(socket:soc, data:'USER ' + rand_str(length:8) + '\r\n');
 r = recv_line(socket:soc, length:1024);
 close(soc);
 if ( r !~ "^(\+OK|-ERR)" ) exit(0);
 report = '\nRemote POP server banner :\n\n' + line;
 security_note(port:port, extra:report);
}
