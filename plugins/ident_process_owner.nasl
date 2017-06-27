#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14674);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");

 script_name(english: "identd Service UID Association");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to determine which user is running the remote service." );
 script_set_attribute(attribute:"description", value:
"By using the identd server (RFC 1413), it is possible to determine the 
process owner of the remote service.");
 script_set_attribute(attribute:"solution", value:
"Block access to, or remove the identd service." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Get UIDs with identd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("find_service1.nasl", "slident.nasl", "ident_backdoor.nasl");
 script_require_ports("Services/auth", 113);
 #script_exclude_keys("Host/ident_scanned");
 exit(0);
}

#

if (! defined_func("get_source_port")) exit(0);

include("misc_func.inc");
include('global_settings.inc');

if (  thorough_tests ) max_pass = 6;
else max_pass = 3;

#if (get_kb_item("Host/ident_scanned")) exit(0);

ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))
  if (COMMAND_LINE)
   for (i = 1; i <= 65535; i ++)
    ports[i] = "Ports/tcp/"+i;
  else
   exit(0);

# Should we only use the first found identd?

list = get_kb_list("Services/auth");
if ( ! isnull(list) ) 
     list = make_list(113, list);
else 
     list = make_list(113);


foreach iport ( list )
{
 if (get_port_state(iport) && ! get_kb_item('fake_identd/'+iport))
 {
  isoc = open_sock_tcp(iport);
  if (isoc) break;
 }
 else
  debug_print('Port ', iport, ' is closed or blacklisted\n');
}
if (! isoc) exit(0);
debug_print('iport=', iport, '\n');

# Try several times, as some ident daemons limit the throughput of answers?!
for (i = 1; i <= max_pass && ! isnull(ports); i ++)
{
 prev_ident_n = identd_n;
 j = 0;
 if (i > 1) debug_print('Pass #', i);
foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 if ( port == 139 || port == 445 ) continue;
 if (get_port_state(port) && ! get_kb_item("Ident/tcp"+port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   debug_print('Testing ', port, '\n');
   req = strcat(port, ',', get_source_port(soc), '\r\n');
   if (send(socket: isoc, data: req) <= 0)
   {
# In case identd does not allow several requests in a raw
    close(isoc);
    isoc = open_sock_tcp(iport);
    if (!isoc) { close(soc); exit(0); }
    send(socket: isoc, data: req);
   }
   id = recv_line(socket: isoc, length: 1024);
   debug_print('Identd(',port,')=', id);
   if (id)
   {
    ids = split(id, sep: ':');
    uid = chomp(ids[3]);
    if ("USERID" >< ids[1] && strlen(uid) < 30 )
    {
     identd_n ++;
     set_kb_item(name: "Ident/tcp/"+port, value: uid);
     security_note(port: port, extra: 'identd reveals that this service is running as user/uid '+uid+'\n');
    }
    else
     bad[j++] = port;
   }
   else
    bad[j++] = port;
   close(soc);
  }
 }
}
 # Exit if we are running in circles
 if (prev_ident_n == identd_n) break;
 ports = NULL;
 foreach j (bad) ports[j] = j;
 bad = NULL;
}
if (-- i > 1) debug_print(i, ' passes were necessary');

close(isoc);
set_kb_item(name: "Host/ident_scanned", value: TRUE);

