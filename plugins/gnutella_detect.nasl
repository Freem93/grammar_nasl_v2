#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10946);
 script_version ("$Revision: 1.31 $");
 script_cvs_date("$Date: 2011/07/02 20:35:07 $");

 script_name(english:"Gnutella Servent Detection");
 script_summary(english:"Detect Gnutella servent");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a P2P file sharing application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Gnutella 'servent', a P2P file sharing
application." );
 script_set_attribute(attribute:"solution", value:
"Remove this software if it does not agree with your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/04/30");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_dependencie("find_service1.nasl", "httpver.nasl");
 # Gnutella servent _might_ be detected as a web server
 script_require_ports("Services/www", 6346);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
 local_var banner, soc, answer, answer2, rep;
 if (! get_port_state(port))
  return (0);

 banner = get_http_banner(port: port);
 if ( banner && "DAAP-Server: iTunes" ><  banner ) return 0;

 soc = open_sock_tcp(port);
 if (! soc) exit(0);

 # Not a full request...
 send(socket: soc, data: 'GNUTELLA CONNECT/0.6\r\n\r\n');
 answer = recv_line(socket:soc, length: 256);
 if (ereg(string: answer, pattern: "^GNUTELLA/0\.6 [0-9][0-9][0-9] "))
 {
   answer2 = recv(socket:soc, length: 2048);
   close(soc);
   rep = 'The Gnutella servent supports the GNUTELLA/0.6 protocol version.\n';
   if (egrep(string: answer2, pattern: "^X-Ultrapeer: *False", icase: 1))
   {
     rep = strcat(rep, 'It is a leaf node.\n');
     set_kb_item(name: 'gnutella/'+port+'/type', value: 'leaf');
   }
   else if (egrep(string: answer2, pattern: "^X-Ultrapeer: *True", icase: 1))
   {
     rep = strcat(rep, 'It is an ultrapeer node.\n');
     set_kb_item(name: 'gnutella/'+port+'/type', value: 'ultrapeer');
   }
   if (report_verbosity > 1)
    rep = strcat(rep, '\nThe Gnutella servent answered :\n\n', 
    	beginning_of_response(resp: strcat(answer, answer2)));
   security_note(port:port, protocol:"tcp", extra: rep);
   # if (COMMAND_LINE) display(rep);
   register_service(port:port, proto:"gnutella");
   set_kb_item(name: 'gnutella/'+port+'/version', value: '0.6');
   return(1);
 }
 close(soc);

 soc = open_sock_tcp(port);
 if (! soc) exit(0);
 send(socket:soc, data: 'GNUTELLA CONNECT/0.4\r\n\r\n');
 answer = recv_line(socket:soc, length: 256);
 if ("GNUTELLA OK" >< answer)
 {
   answer2 = recv(socket:soc, length: 2048);
   close(soc);
   rep = 'The Gnutella servent supports the GNUTELLA/0.4 protocol version.\n';
   if (report_verbosity > 1) rep = strcat(rep, '\nThe Gnutella servent answered :\n\n', answer, answer2);
   security_note(port:port, protocol:"tcp", extra: rep);
   # if (COMMAND_LINE) display(rep);
   register_service(port:port, proto:"gnutella");
   set_kb_item(name: 'gnutella/'+port+'/version', value: '0.4');
   return(1);
  }
 close(soc); 
 if (! banner)
  return(0);

 # We should probably add more regex here. But there are 100+ Gnutella
 # variants.
 if (egrep(pattern:"Gnutella|BearShare", string:banner, icase:1))
 {
rep = 
"Although this service did not answer to Gnutella protocol 0.4 or 0.6,
it might be a Gnutella server.";

  security_note(port:port, protocol:"tcp",extra:rep);
  return(1);
 }
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:6346);
foreach port (ports) check(port:port);
