#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11389);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/01/15 21:39:12 $");

 script_name(english:"rsync Service Detection");
 script_summary(english:"Shows the remotely accessible rsync modules.");

 script_set_attribute(attribute:"synopsis", value:
"The remote synchronization service is remotely accessible.");
 script_set_attribute(attribute:"description", value:
"The remote rsync server can be accessed remotely.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Rsync" );
 script_set_attribute(attribute:"solution", value:
"Limit access to the service if desired.");
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl");
 script_require_ports("Services/rsyncd", 873);
 exit(0);
}

function rsync_init(port, motd)
{
 local_var soc, r, q, i;
  
 soc = open_sock_tcp(port);
 if(!soc)return NULL;
 r = recv_line(socket:soc, length:4096);
 if ( isnull(r) )
 {
  close(soc);
  return NULL;
 }
 if(motd) q = recv(socket:soc,length:strlen(motd), min:strlen(motd));
 send(socket:soc, data:r);
 return soc;
}

port = get_kb_item("Services/rsyncd");
if(!port)port = 873;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

welcome = recv_line(socket:soc, length:4096);
send(socket:soc, data:string("@BOGUS\n"));
if(!welcome)exit(0);
motd = NULL;

set_kb_item(name:"rsyncd/" + port + "/banner", value:welcome);

for(i=0;i<1024;i++)
{
 r = recv_line(socket:soc, length:4096);
 if(!strlen(r) || "@ERROR" >< r)break;
 else motd += r;
} 
close(soc);

soc = rsync_init(port:port, motd:motd);
send(socket:soc, data:string("#list\r\n"));

modules = NULL;


for(i=0;i<255;i++)
{
 r = recv_line(socket:soc, length:4096);
 if(!r || "@RSYNC" >< r)break;
 modules += r;
}

close(soc);

if (modules != NULL )
{
  d = NULL;
  foreach module (split(modules))
  {
   m = split(module, sep:" ");
   soc = rsync_init(port:port, motd:motd);
   if(soc)
   {
    send(socket:soc, data:string(m[0]  - " ", "\r\n"));
    r = recv_line(socket:soc, length:4096);
    if("@RSYNCD: OK" >< r)d += " - " + (module  - string("\n") ) + string(" (readable by anyone)\n");
    else d += " - " + (module - string("\n")) + string(" (authentication required)\n");
    close(soc);
   }
  }

 report = NULL;

 if( motd != NULL ) report = string("The remote 'message of the day' is :\n\n", motd, "\n");
 report += string("The following rsync modules are available :\n\n", d);

 if("(readable by anyone)" >< report) security_note(port:port, extra:report);
 else security_note(port:port, extra:report);
}
