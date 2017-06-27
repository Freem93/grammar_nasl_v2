#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33868);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id("CVE-2008-3337");
 script_bugtraq_id(30587);
 script_osvdb_id(47587);

 script_name(english:"PowerDNS Authoritative Server Malformed Query Cache Poisoning Weakness");
 script_summary(english: "Sends a malformed query to the DNS server and wait for an answer");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS server drops malformed queries.");
 script_set_attribute(attribute:"description", value:
"The remote DNS drops malformed queries.  If it is not just a resolver
and serves a domain name, this may help poisoning the cache of other
DNS resolvers.  PoweDNS 2.9.21 and earlier are known to exhibit this
behavior. 

Note that this does not mean that this server would be vulnerable 
to cache poisoning if it were a resolver.");
 script_set_attribute(attribute:"solution", value:"Upgrade PowerDNS to version 2.9.21.1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"see_also", value:"http://doc.powerdns.com/powerdns-advisory-2008-02.html");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencie("dns_server.nasl", "bind_version.nasl");
 script_require_keys("DNS/udp/53");
 exit(0);
}

include("dns_func.inc");
include("global_settings.inc");

bind_version = get_kb_item("bind/version");
if (paranoia_level < 2 && "POWERDNS" >!< bind_version) exit(0);
# If version-string=powerdns, the answer is:
# "Served by PowerDNS - http://www.powerdns.com"
# If version-string=full, the answer is:
# "Served by POWERDNS 2.9.21.1 ..."

# http://www.iana.org/assignments/dns-parameters
dns["transaction_id"] = rand() & 0xffff;
dns["flags"]	      = 0x0010;
dns["q"]	      = 1;
packet1 = mkdns(dns: dns, 
       	 	query:mk_query(txt:mk_query_txt("test", "example", "com"),
		type: 1,	# A
		class: 1));	# IN

dns["transaction_id"] = rand() & 0xffff;
dns["flags"]	      = 0x0010;
dns["q"]	      = 1;
packet2 = mkdns(dns: dns, 
       	 	query:mk_query(txt:mk_query_txt(" test", "example", "com"),
		type: 1,	# A
		class: 1));	# IN

function check(packet, proto, socket)
{
  local_var	len, len_hi, len_lo, req, r;

  if (proto == 'tcp')
  {
    len = strlen(packet);
    len_hi = len / 256;
    len_lo = len % 256;
    req = string(raw_string(len_hi, len_lo), packet);
  }
  else
    req = packet;
  send(socket: socket, data: req);
  r = recv(socket:socket, length: 512);
  return strlen(r) > 0;	# Should we check that it is a valid DNS packet?
}

port = get_kb_item("Services/dns"); 
if (port > 0 && get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    if ( check(packet: packet1, proto: 'tcp', socket: soc) &&
       ! check(packet: packet2, proto: 'tcp', socket: soc) )
      security_hole(port: port, proto: 'tcp');
    close(soc);
    exit(0);
  }
}

if (get_kb_item("DNS/udp/53") && get_udp_port_state(53))
{
  soc = open_sock_udp(53);
  if(soc)
  {
    if ( check(packet: packet1, proto: 'udp', socket: soc) &&
       ! check(packet: packet2, proto: 'udp', socket: soc) )
      security_hole(port: 53, proto: 'udp');
    close(soc);
    exit(0);
  }
}
