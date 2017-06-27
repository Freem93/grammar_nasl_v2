# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(18373);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2011/03/11 21:52:38 $");

  script_name(english:"slident / fake identd Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote ident server returns random tokens." );
 script_set_attribute(attribute:"description", value:
"The remote ident/authd server returns random tokens instead of leaking
real user IDs (this is a good thing).  It may be slidentd or some
other fake identd." );
 script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc1413" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

  script_family(english: "Service detection");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english: "Detect identd servers that return random tokens");
  script_category(ACT_GATHER_INFO);
  script_copyright(english: "This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_require_ports("Services/auth", 113);
  script_dependencies("find_service1.nasl", "ident_backdoor.nasl");
  exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');

iport = get_kb_item("Services/auth");
if(! iport) iport = 113;
if (! get_port_state(iport) || get_kb_item('fake_identd/'+iport)) exit(0);

port = get_host_open_port();
if (! port || port == 139 || port == 445 ) port = iport;

debug_print(level: 2, 'port=', port, ', iport=', iport);

j = 0;
for (i = 0; i < 3; i ++)	# Try more than twice, just in case
{
 soc = open_sock_tcp(port);
 if (soc)
 {
  req = strcat(port, ',', get_source_port(soc), '\r\n');
  isoc = open_sock_tcp(iport);
  if (isoc)
  {
   send(socket: isoc, data: req);
   id = recv_line(socket: isoc, length: 1024);
   if (id)
   {
    ids = split(id, sep: ':');
    if ("USERID" >< ids[1])
    {
     got_id[j ++] = ids[3];
     debug_print('ID=', ids[3], '\n');
    }
   }
   close(isoc);
  }
  close(soc);
 }
}

slident = 0;
if (j == 1)
{
 # This is slidentd
 if (got_id[0] =~ '^[a-f0-9]{32}$')
 {
  debug_print('slident detected on port ', iport, '\n');
  slident = 1;
 }
}
else
 for (i = 1; i < j; i ++)
  if (got_id[i-1] != got_id[i])
  {
   slident = 1;	# Maybe not slident, but a fake ident anyway
   debug_print('Ident server on port ', iport, ' returns random tokens: ',
	chomp(got_id[i-1]), ' != ', chomp(got_id[i]), '\n');
   break;
  }

if (slident)
{
  security_note(port: iport);
  set_kb_item(name: 'fake_identd/'+iport, value: TRUE);
}
