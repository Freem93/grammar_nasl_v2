#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35372);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");

 script_name(english:"DNS Server Dynamic Update Record Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote DNS server allows dynamic updates." );
 script_set_attribute(attribute:"description", value:
"It was possible to add a record into a zone using the DNS dynamic
update protocol, as described by RFC 2136. 

This protocol can be used by DHCP clients to enter their host names
into the DNS maps, but it could be subverted by malicious users to
redirect network traffic." );
 script_set_attribute(attribute:"solution", value:
"Ignore this warning if the scanner address is in the range of IP
addresses that are allowed to perform updates. 

Limit addresses that are allowed to do dynamic updates (eg, with
BIND's 'allow-update' option) or implement TSIG or SIG(0)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


 script_summary(english: "Insert a random record into a DNS zone");
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencies("bind_hostname.nasl", "dns_server.nasl");
 script_require_keys("DNS/udp/53");
 exit(0);
}

#

include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");

function dns_update_A(zone, name, delete)
{
  local_var	pkt;

  pkt = raw_string(
      rand() % 256, rand() % 256,	# Transaction ID
      0x28, 0x00,			# Flags: opcode = 5 (dynamic update)
      0, 1,				# zones: 1
      0, 0,				# Prerequesites: 0
      0, 1,				# updates: 1
      0, 0);				# additional RRs: 0
  pkt += dns_str_to_query_txt(zone);
  pkt += raw_string(
      0, 6,		# SOA
      0, 1);		# IN
  pkt += raw_string(strlen(name) % 255) + name;	# No null byte after that!
  pkt += raw_string(
      0xC0, 0x0C,	#
      0, 1);		# A
  if (delete)
    pkt += raw_string(
      0, 0xFE,		# None
      0, 0, 0, 0);	# No TTL
  else
    pkt += raw_string(
      0, 1,		# IN
      0, 0, 0, 60);	# TTL = 1 min
  pkt += raw_string(
      0, 4,		# Data length
      127, 1, 2, 3);
  return pkt;
}

if (! COMMAND_LINE && ! get_kb_item("DNS/udp/53")) exit(0);
port = 53;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

name1 = get_host_name();
name2 = get_kb_item("bind/hostname");

zones_l = make_list();
i = 0;
foreach n (list_uniq(name1, name2))
{
  # We cannot test if we do not have a proper zone name
  if ( isnull(n) || "." >!< n || 
       n =~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\.in-addr\.arpa\.?)?$")
    continue;

  z = n; 
  while (match(string: z, pattern: "*."))
    z = substr(z, 0, strlen(z) - 2);
  while (strlen(z) > 0)
  {
    zones_l[i++] = z;  
    z = strstr(z, '.');
    if (strlen(z) <= 1) break;
    z = substr(z, 1);
  }
}

zones_l = list_uniq(zones_l);

dynname = rand_str(length: 16, charset: "abcdefghijklmnopqrstuvwxyz");

soc = open_sock_udp(53);
if (! soc) exit(0);

foreach zone (zones_l)
{
 pkt = dns_update_A(zone: zone, name: dynname);
 send(socket:soc, data: pkt);

 r = recv(socket:soc, length:1024);
 if(strlen(r) > 3)
  {
   flags1 = ord(r[2]); flags2 = ord(r[3]);
   if ((flags1 & 0xF8) == 0xA8 && (flags2 & 0xF) == 0)
   {
     # Check
     dns["transaction_id"] = rand() % 65535;
     dns["flags"]	   = 0x0010;
     dns["q"]		   = 1;
     packet = mkdns(dns: dns, 
      query: mk_query( txt: dns_str_to_query_txt(dynname + "." + zone), 
      	     	       type: 0x000c, class: 0x0001) );
     send(socket:soc, data:packet);
     r = recv(socket:soc, length:1024);
     if (strlen(r) > 3)
     {
       flags1 = ord(r[2]); flags2 = ord(r[3]);
       # Absurd: we get a "no such name" answer to our query although the
       # update was supposed to work
       if ((flags & 0x80) && (flags2 & 0xF) == 3) break;
     }
     e = strcat('\nNessus was able to register a new A record into the following zone :\n\n', zone, '\n');
     security_warning(port: 53, proto: "udp", extra: e);
     pkt = dns_update_A(zone: zone, name: dynname, delete: 1);
     send(socket:soc, data: pkt);
     break;
     set_kb_item(name: "DNS/dyn_update_zone", value: zone);
   }
  }
}
 
close(soc);
