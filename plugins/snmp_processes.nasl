#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10550);
 script_version ("$Revision: 1.26 $");
 
 script_name(english:"SNMP Query Running Process List Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of processes running on the remote host can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of running processes on the remote
host by sending SNMP requests with the OID 1.3.6.1.2.1.25.4.2.1.2

An attacker may use this information to gain more knowledge about
the target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/13");
 script_cvs_date("$Date: 2011/05/24 20:37:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Enumerates processes via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (! soc) exit (1, "Could not open socket to UDP port "+port+".");

oid = "1.3.6.1.2.1.25.4.2.1.2";

soid = oid;
re =  strcat("^",str_replace(string:oid, find:".", replace:'\\.'), '\\.');

report = '';
while(1)
{
  z = snmp_request_next (socket:soc, community:community, oid:soid);
  if (!isnull(z) && egrep (pattern:re,string:z[0]))
  {
   name = z[1];
   soid = z[0];
   p = z[0] - (oid+'.');
   cmdline = snmp_request(socket: soc, community:community, 
   	  oid:  '1.3.6.1.2.1.25.4.2.1.5.'+p);
   cpu = snmp_request(socket: soc, community:community, 
       oid: '1.3.6.1.2.1.25.5.1.1.1.'+p);
   cpu = int(cpu) / 100; cpu = strcat(cpu);
   mem = snmp_request(socket: soc, community:community, 
       oid: '1.3.6.1.2.1.25.5.1.1.2.'+p);
   mem = strcat(mem);
   t1 = 5 - strlen(p); if (t1 < 0) t1 = 0;
   t2 = 6 - strlen(cpu); if (t2 < 1) t2 = 1;
   t3 = 6 - strlen(mem); if (t3 < 1) t3 = 1;
   t4 = 16 - strlen(name); if (t4 < 1) t4 = 1;
   report = strcat(report,
   	  crap(data:' ', length: t1), p, 
   	  crap(data:' ', length: t2), cpu, 
	  crap(data:' ', length: t3), mem,
	  ' ', name, crap(data:' ', length: t4),
	  cmdline, '\n');
  }
  else
    break;
 }

if (strlen(report) > 0)
{
  report = strcat('\n  PID   CPU   MEM COMMAND           ARGS\n', report);
  security_note(port:port, extra:report, protocol:"udp");
}
