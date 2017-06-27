#
# (C) Tenable Network Security, Inc.
#

# References:
# RFC 1058	Routing Information Protocol
# RFC 2453	RIP Version 2
#
# Notes:
# routed from OpenBSD or Linux rejects routes that are not sent by a neighbour
# 
# This plugin will only reports attacks on a WAN - see rip_poison_lan.nasl
# for a similar check on a LAN.

include("compat.inc");

if(description)
{
  script_id(11829);
  script_version ("$Revision: 1.20 $");

  script_name(english: "RIP Poisoning Routing Table Modification");
  script_summary(english: "Poison routing tables through RIP");
 
  script_set_attribute(attribute:"synopsis", value:
"Routing tables can be modified." );
  script_set_attribute(attribute:"description", value:
"The remote RIP listener accepts routes that are not sent by a
neighbor. 

This cannot happen in the RIP protocol as defined by RFC2453, and
although the RFC is silent on this point, such routes should probably
be ignored. 

A remote attacker might use this flaw to access the local network if
it is not protected by a properly configured firewall, or to hijack
connections." );
  script_set_attribute(attribute:"solution", value:
"Either disable the RIP listener if it is not used, use RIP-2 in
conjunction with authentication, or use another routing protocol." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/03");
 script_cvs_date("$Date: 2016/05/26 16:14:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

# This plugin is not supposed to be dangerous but it was released as 
# ACT_DESTRUCTIVE_ATTACK because we could not be 100% sure that there 
# were no really broken RIP implementation somewhere in the cyberspace. 
# Looks OK now.
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english: "Misc.");
  script_dependencie("rip_detect.nasl");
  script_require_keys("Services/udp/rip");
  exit(0);
}

##include("dump.inc");

port = get_kb_item("Services/udp/rip");
if (! port) port = 520;

#if (! get_udp_port_state(port)) exit(0); # Not very efficient with UDP!

a1 = 192; a2 = 0; a3 = 34; a4 =  166;	# example.com

function check_example_com()
{
  local_var broken, fam, i, l, r, req, soc, ver; 
  
  broken = get_kb_item("rip/" + port + "/broken_source_port");
  if (broken)
    soc = open_priv_sock_udp(dport:port, sport:port);
  else
    soc = open_sock_udp(port);
  if (!soc) return(0);

  # Special request - See SS3.4.1 of RFC 1058
  req = raw_string(1, 1, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 16);
  send(socket: soc, data: req);
  r = recv(socket:soc, length: 512);
  ##dump(ddata: r, dtitle: "routed");

  close(soc);
  l = strlen(r);
  if (l < 4 || ord(r[0]) != 2) return (0);	# Not a RIP answer
  ver = ord(r[1]); 
  if (ver != 1 && ver != 2) return (0);	# Not a supported RIP version?

  for (i = 4; i < l; i += 20)
  {
    fam = 256 * ord(r[i]) + ord(r[i+1]);
    if (fam == 2)
      if (ord(r[i+4]) == a1 && ord(r[i+5]) == a2
	&& ord(r[i+6]) == a3  && ord(r[i+7]) == a4 # Addr
# We ignore route which have 'infinite' length
	&& ord(r[i+16]) == 0 && ord(r[i+17]) == 0 
	&& ord(r[i+18]) == 0 && ord(r[i+19]) != 16) # Hops
        return 1;
  }
  return 0;
}

if (check_example_com()) exit(0);	# Routing table is weird

soc = open_priv_sock_udp(sport: port, dport: port);
if (! soc) exit(0);


req = raw_string(2, 1, 0, 0, 
		0, 2, 0, 0, 
		a1, a2, a3, a4,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 14);	# Hops - limit the propagation of the bogus route
# Maybe we should use the result of traceroute to set the right number?

send(socket: soc, data: req);
##close(soc);

if (check_example_com())
{
  if (! islocalnet())
    security_hole(port: port, protocol: "udp");
  set_kb_item(name: 'rip/'+port+'/poison', value: TRUE);

# Fix it: set the number of hops to "infinity".

  req = raw_string(2, 1, 0, 0, 
		0, 2, 0, 0, 
		a1, a2, a3, a4,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 16);	# Hops
  send(socket: soc, data: req);
}

close(soc);

##if (! check_example_com()) display("Fixed!\n");
