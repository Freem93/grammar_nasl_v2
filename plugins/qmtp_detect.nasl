#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11134);
  script_version ("$Revision: 1.13 $");
 
  script_name(english:"QMTP/QMQP Server Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A QMTP/QMQP server is running on this port." );
 script_set_attribute(attribute:"description", value:
"A QMTP/QMQP server is running on this port.
QMTP is a proposed replacement of SMTP by D.J. Bernstein.

** Note that Nessus only runs SMTP tests currently." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/22");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english: "Detect QMTP servers");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service1.nasl", "find_service2.nasl");
  script_require_ports(209, 628);

  exit(0);
}

####

include("global_settings.inc");
include("misc_func.inc");
include("network_func.inc");

function netstr(str)
{
  local_var	l;

  l = strlen(str);
  return strcat(l, ":", str, ",");
}

global_var	tested;
tested = make_list();

function test(port)
{
  local_var	soc, r, msg, srv;

  if (tested[port]) return;
  tested[port] = 1;

  soc = open_sock_tcp(port);
  if (!soc) return;

  msg = strcat(netstr(str: "
Message-ID: <1234567890.666.nessus@example.org>
From: nessus@example.org
To: postmaster@example.com

Nessus is probing this server.
"), 
	netstr(str: "nessus@example.org"),
	netstr(str: netstr(str: "postmaster@example.com")));
  # QMQP encodes the whole message once more
  if (port == 628)
  {
     msg = netstr(str: msg);
     srv = "QMQP";
  }
  else
    srv = "QMTP";

  send(socket: soc, data: msg);
  r = recv(socket: soc, length: 1024);
  close(soc);

  if (ereg(pattern: "^[1-9][0-9]*:[KZD]", string: r))
  {
    security_note(port);
    register_service(port: port, proto: srv);
  }

  if (ereg(pattern: "^[1-9][0-9]*:K", string: r))
  {
    # K: Message accepted for delivery
    # Z: temporary failure
    # D: permanent failure
    set_kb_item(name: "QMTP/relay/"+port, value: TRUE);
   }
}

ports = get_kb_list("Services/QMTP");
if (! isnull(ports))
  foreach port (ports)
    if (service_is_unknown(port: port) && get_port_state(port))
      test(port: port);

ports = get_kb_list("Services/QMQP");
if (! isnull(ports))
  foreach port (ports)
    if (service_is_unknown(port: port) && get_port_state(port))
      test(port: port);

foreach port (make_list(209, 628))
  if (service_is_unknown(port: port) && get_port_state(port))
    test(port: port);
