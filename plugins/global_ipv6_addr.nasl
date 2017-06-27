#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(45405);
 script_version ("$Revision: 1.3 $");
 script_cvs_date("$Date: 2012/08/07 18:20:28 $");
 
 script_name(english:"Reachable IPv6 address");
 script_summary(english:"Reachable IPv6 addresses");
             
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be reachable from the Internet.");
 script_set_attribute(attribute:"description", value:
"Although this host was scanned through a private IPv4 or local scope
IPv6 address, some network interfaces are configured with global scope
IPv6 addresses.  Depending on the configuration of the firewalls and
routers, this host may be reachable from Internet.");
 script_set_attribute(attribute:"solution", value:
"Disable IPv6 if you do not actually using it. 

Otherwise, disable any unused IPv6 interfaces and implement IP
filtering if needed.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/02");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");
 script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
 script_dependencie("ifconfig_inet6.nasl", "icmp_niq.nasl", "wmi_list_interfaces.nbin");
 exit(0);
}

include("global_settings.inc");
include("network_func.inc");

if (! is_private_addr()) exit(0, "The remote host has a public address.");

l = make_list();
a = get_kb_list("Host/ifconfig/IP6Addrs");
if (! isnull(a)) l = make_list(l, a);
a = get_kb_list("Host/ICMP/NIQ/IP6Addrs");
if (! isnull(a)) l = make_list(l, a);
a = get_kb_list("Host/WMI/IP6Addrs");
if (! isnull(a)) l = make_list(l, a);

if (max_index(l) == 0) exit(0, "No IPv6 addresses are known for this host.");

z = make_array(); a = NULL; rep = "";
foreach a (l)
  if (! z[a] && a !~ "^f...:" && a !~ "^(0*:)+:0*1$")
  {
    z[a] = 1;
    rep = strcat(rep, '  - ', a, '\n');
  }

if (! rep) exit(0, "All IPv6 addresses are local scope addresses.");

if (max_index(split(rep)) > 1) s = "s were";
else s = " was";

security_note(port: 0, extra: 
  '\nThe following global address'+s+' gathered :\n\n' + rep );
