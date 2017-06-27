#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35371);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2011/09/14 15:27:29 $");

 script_name(english:"DNS Server hostname.bind Map Hostname Disclosure");
 script_summary(english: "Query hostname.bind in the CHAOS domain");
 
 script_set_attribute(attribute:"synopsis", value:
"The DNS server discloses the remote host name.");
 script_set_attribute(attribute:"description", value:
"It is possible to learn the remote host name by querying the remote
DNS server for 'hostname.bind' in the CHAOS domain.");
 script_set_attribute(attribute:"solution", value:
"It may be possible to disable this feature.  Consult the vendor's
documentation for more information.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "DNS");

 script_dependencies("dns_server.nasl");
 script_require_keys("DNS/udp/53");

 exit(0);
}

include("dns_func.inc");
include("byte_func.inc");


if (! COMMAND_LINE && ! get_kb_item("DNS/udp/53")) exit(0);
port = 53;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

dns["transaction_id"] = rand() & 0xffff;
dns["flags"]	      = 0x0010;
dns["q"]	      = 1;
packet = mkdns(dns:dns, 
       query:mk_query(txt:mk_query_txt("HOSTNAME", "BIND"),
       type: 0x0010, class: 0x0003));
soc = open_sock_udp(53);
send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
close(soc);
response  = dns_split(r);
if ( isnull(response) ) exit(0);
f = response["flags"];


if (f  & 0x8000 && !( f & 0x0003 ))
{
  h = get_query_txt(response["an_rr_data_0_data"]);
  if (isnull(h)) exit(0);
  set_kb_item(name:"bind/hostname", value: h);
  report = '\nThe remote host name is :\n\n' + h + '\n';
  security_note(port:53, proto: "udp", extra:report);
}
