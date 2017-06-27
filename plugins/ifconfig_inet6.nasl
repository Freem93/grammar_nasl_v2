#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25202);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2017/01/26 18:40:45 $");

 script_name(english:"Enumerate IPv6 Interfaces via SSH");
 script_summary(english:"Uses the result of 'ifconfig -a' or 'ip addr show'.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the IPv6 interfaces on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the network interfaces configured with
IPv6 addresses by connecting to the remote host via SSH using the
supplied credentials.");
 script_set_attribute(attribute:"solution", value:
"Disable IPv6 if you are not actually using it. Otherwise, disable any
unused IPv6 interfaces.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

 script_dependencie("ssh_get_info.nasl");
 script_require_keys("Host/uname");
 script_require_ports("Host/ifconfig", "Host/netstat-ianf-inet6");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

uname = get_kb_item_or_exit("Host/uname");
ifaces = NULL;
dev = NULL;
dev_ip_count = make_array();

# HP-UX
if ('HP-UX' >< uname)
{
  netstat = get_kb_item_or_exit("Host/netstat-ianf-inet6");
  lines = split(netstat, keep:FALSE);
  netstat_pat = "^([^\s]+)\s+[0-9]+\s+([0-9a-fA-F:%]+)(\/[0-9]+)?(?:\s+[0-9]+)+";
  foreach line (lines)
  {
    match = eregmatch(pattern:netstat_pat, string:line);
    if (isnull(match)) continue; # next

    iface_name = match[1];
    ip_addr = match[2]; #ipv6

    if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
    else dev_ip_count[iface_name]++;

    ifaces += ' - ' + ip_addr + ' (on interface ' + iface_name + ')\n';

    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/ipv6", value:ip_addr);
    set_kb_item(name:"Host/ifconfig/IP6Addrs", value: ip_addr);
  }
}
else
{
  ifconfig = get_kb_item_or_exit("Host/ifconfig");
  inet6 = egrep(pattern:"inet6", string:ifconfig);
  if ( isnull(inet6) ) exit(0, 'No IPv6 addresses found.');

  lines = split(ifconfig, keep:FALSE);
  ifconfig_regex = "^(\d+: )?([a-z\-]+[\-a-z0-9]+(:[0-9]+)?)[: ].*";
  foreach line ( lines )
  {
    if ( line =~ ifconfig_regex )
    {
      dev = ereg_replace(pattern:ifconfig_regex, replace:"\2", string:line);
      if ( dev == line ) dev = NULL;
      if (!isnull(dev)) dev_ip_count[dev] = 0;
    }

    if  ( "inet6" >< line )
    {
      addr = ereg_replace(pattern:".*inet6( addr:)? ([0-9a-f:]*).*", string:line, replace:"\2");
      if ( !empty_or_null(addr) && addr != line )
      {
        ifaces += ' - ' + addr;
        set_kb_item(name: "Host/ifconfig/IP6Addrs", value: addr);
        if ( !empty_or_null(dev) )
        {
          ifaces += ' (on interface ' + dev + ')';
          dev_ip_count[dev]++;
          # for reporting
          set_kb_item(name:"Host/iface/"+dev+"/ipv6", value: addr);
          set_kb_item(name:"Host/iface/id", value:dev);
        }
        ifaces += '\n';
      }
    }
  }
}

foreach dev (keys(dev_ip_count))
{
  aliased = dev_ip_count[dev] > 1;
  if (aliased)
    set_kb_item(name:"Host/iface/"+dev+"/aliased", value:TRUE);
}

if ( strlen(ifaces) )
{
 security_note(port:0, extra:'\nThe following IPv6 interfaces are set on the remote host :\n\n' + ifaces);
}
else exit(1, 'Unable to parse any IPv6 addresses.');
