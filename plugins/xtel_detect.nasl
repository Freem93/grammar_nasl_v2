#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11121);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");
 
  script_name(english:"xtel Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a terminal emulation service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running xteld, a Minitel emulator. This service
allows users to connect to the Teletel network. Some of the servers
are expensive. Note that by default, xteld forbids access to the most
expensive services." );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Detects xteld");
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service1.nasl");
  script_require_ports(1313);

  exit(0);
}

#
include ("global_settings.inc");
include ("misc_func.inc");

function read_xteld(s)
{
  local_var len, m, r, r1, r2;

  m = "";
  while (1)
  {
    r = recv(socket: s, length: 1);
    if (strlen(s) == 0) return (m);
    len = ord(r);
    if (len == 130) return (m);
    r1 = recv(socket: s, length: len);
    send(socket: s, data: raw_string(0x83));
    r = recv(socket: s, length: 1);
    if (strlen(s) == 0) return (m);
    len = ord(r);
    if (len == 130) return (m);
    r2 = recv(socket: s, length: len);
    send(socket: s, data: raw_string(0x82));
    m = string(m, r1, " - ", r2, "\n");
  }
}

req1 = raw_string(6) + "Nessus" + raw_string(0x82);

# Quick way
port=1313;

# Slow way
#port = get_kb_item("Services/unknown"); 
#if (! port) port=1313;

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: req1);
m1 = read_xteld(s: soc);
close(soc);

if (m1)
{
  m2 = string(
"Here are the authorized services :\n",
	m1); 
  security_note(port: port, extra: m2);
  register_service(port: port, proto: "xtel");
}


