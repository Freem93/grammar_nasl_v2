#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(49689);
 script_version ("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");

 script_name(english:"RSP Detection");
 script_summary(english:'Detect RSP monitoring agent.');

 script_set_attribute(attribute:"synopsis", value:
"A supervision software is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"An RSP agent is running on this port.  RSP is an agent-based system
management and monitoring tool from Draconis Software." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2472cd65");
 script_set_attribute(attribute:"see_also", value:"http://www.draconis.com/blog/2008/06/04/new-draconis-software-site-design/");
 script_set_attribute(attribute:"solution", value:
"Consider moving to an alternative application since RSP is no longer
maintained." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/27");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_dependencie('find_service2.nasl');
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_require_ports(3497, "Services/unknown");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

buf0 = '';
function readuntil0(s, zap)
{
  local_var	n, l, r;

  l = -1;
  if (strlen(buf0) > 0) l = stridx(buf0, '\0');
  if (l < 0)
  {
    r = recv(socket:s, length:8192);
    if (strlen(r) > 0)
    {
      buf0 += r;
      l = stridx(buf0, '\0');
    }
  }
  if (l < 0) return NULL;

  if (zap)
    r = substr(buf0, 0, l - 1);
  else
    r = substr(buf0, 0, l);
  buf0 = substr(buf0, l + 1);
  return r;
}

if (! get_kb_item("global_settings/disable_service_discovery"))
{
  # As we check the banner later, we can afford to test all unknown ports
  port = get_unknown_svc(3497);
  if (!port) exit(0, "There are no unknown services.");
  if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
}
else
{
  port = 3497;
  if (! get_port_state(port)) exit(0, "Port "+port+" is not open.");
  if (! service_is_unknown(port: port))
    exit(0, "The service listening on port "+port+" has already been identified.");
}

# RSP sends a banner to GET or HELP request => dontfetch is set
b = get_unknown_banner(port: port, dontfetch: 1);
if (isnull(b)) exit(0, "The service listening on port "+port+" does not respond with a banner.");
if (! match(string: b, pattern: 'RSPSENDACK*'))
  exit(0, "The banner from the service listening on port "+port+" does not start with RSPSENDACK.");


s = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");
send(socket: s, data: 'RSPR00000\0');
r = readuntil0(s: s);
if (!r) exit(0, "The service listening on port "+port+" did not respond.");
if (r != 'RSPSENDACK\0')
{
  close(s);
  exit(0, "The service listening on port "+port+" did not respond with RSPSENDACK.");
}

if (report_verbosity > 0)
{
  r = readuntil0(s: s, zap: 1);
  txt = r + '\n'; 

  for (i = 0; i < 64; i ++)
  {
    send(socket: s, data: 'RSPSENDACK\0');
    r = readuntil0(s: s, zap: 1);
    if (strlen(r) == 0) break;
    if (r == '0') txt += '\n';
    else if (strlen(r) > 160) txt += '[...]\n';
    else txt += r + '\n';
  } 
}
close(s);

register_service(port: port, proto: 'rsp');
if (report_verbosity > 0) security_note(port:port, extra:'\nThe RSP service returned the following information :\n\n' + txt);
else security_note(port);
