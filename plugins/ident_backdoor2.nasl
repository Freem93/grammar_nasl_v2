# Written by Michel Arboi <mikhail@nessus.org>
# I'm not sure what this backdoor is...
#


include("compat.inc");

if(description)
{
 script_id(18392);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host seems to be running an ident server, but before any 
request is sent, the server gives an answer about a connection 
to port 6667.

It is very likely this system has been compromised by an IRC 
bot and is now a 'zombie' that can participate in 'distributed 
denial of service' (DDoS) attacks." );
 script_set_attribute(attribute:"solution", value:
"Disinfect or re-install your system." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name(english: "IRC Bot Detection");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Fake IDENT server (IRC bot)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_ports("Services/fake-identd", 113);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");

regex = '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+';

port = get_kb_item('Services/fake-identd');
if (! port) port = 113;

if (! get_port_state(port)) exit(0);

b = get_kb_banner(port: port, type:'spontaneous');
# if (! b) b = get_unknown_banner(port: port);
if (! b) exit(0);

if (b =~ '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+')
{
  security_hole(port);
  set_kb_item(name: 'backdoor/TCP/'+port, value: TRUE);
}
