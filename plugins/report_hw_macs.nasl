#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(86420);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/20 19:30:49 $");

  script_name(english:"Ethernet MAC Addresses");
  script_summary(english:"Consolidates MAC address list.");

  script_set_attribute(attribute:'synopsis', value:
"This plugin gathers MAC addresses from various sources and
consolidates them into a list.");
  script_set_attribute(attribute:'description', value:
"This plugin gathers MAC addresses discovered from both remote probing
of the host (e.g. SNMP and Netbios) and from running local checks
(e.g. ifconfig). It then consolidates the MAC addresses into a single,
unique, and uniform list.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("netbios_name_get.nasl", "ssh_get_info.nasl", "snmp_ifaces.nasl", "bad_vlan.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

global_var CISCO_MAC_RGX    = "[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}";
global_var IFCONFIG_MAC_RGX = "([a-f0-9]{2}[:-]){5}[a-f0-9]{2}";
global_var SOLARIS_MAC_RGX  = "([a-f0-9]{1,2}[:]){5}[a-f0-9]{1,2}";
##
# Validates and normalizes a MAC address
#
# @param mac : required string MAC address to format
#
# @remark formats supported:
#         Cisco    : "0abb.0001.2289"
#         ifconfig : "0A:BB:00:01:22:89"
#         ipconfig : "0A-BB-00-01-22-89"
#         Solaris  : "A:BB:0:1:22:89"
#
# @return mac as  xx:xx:xx:xx:xx:xx (all lower case) or
#         FALSE if mac did not match a known pattern
##
function validate_and_normalize_mac(mac)
{
  if(isnull(mac))
    mac = _FCT_ANON_ARGS[0];

  # Various format regex
  local_var ifconrgx = "^"+IFCONFIG_MAC_RGX+"$";
  local_var ciscorgx = "^"+CISCO_MAC_RGX+"$";
  local_var solarrgx = "^"+SOLARIS_MAC_RGX+"$";
  mac = tolower(mac); # All formats are made lower case

  if(mac =~ ifconrgx)
  {
    mac = ereg_replace(string:mac, pattern:"-", replace:":");
    return mac;
  }
  else if(mac =~ ciscorgx)
  {
    mac = ereg_replace(string:mac, pattern:"\.", replace:":");
    mac = ereg_replace(string:mac, pattern:"([0-9a-f]{2})([0-9a-f]{2})(:|$)", replace:"\1:\2\3");
    return mac;
  }
  else if(mac =~ solarrgx)
  {
    # Solaris likes to show macs like 0:A:32:19:F:AA meaning
    # we have to pad out the missing 0s to normalize it to
    # 00:0A:32:19:0F:AA
    local_var digits = make_list();
    local_var digit  = "";
    mac = split(mac, sep:":", keep:FALSE);
    foreach digit (mac)
    {
      if(strlen(digit) < 2)
        digit = "0"+digit;
      digits = make_list(digits,digit);
    }
    return join(digits,sep:":");
  }
  else return FALSE; # Does not appear to be a valid mac
}

##
# Parses MACs discovered with SNMP
#
# @remark uses KB "SNMP/ifPhysAddress/" (set by snmp_ifaces.nasl)
#
# @return always a list of MACs (maybe empty)
##
function get_snmp_macs()
{
  local_var macs = make_list();
  local_var macidx = 0;
  local_var mac = get_kb_item("SNMP/ifPhysAddress/" + macidx);
  while (!isnull(mac))
  {
    macs[macidx] = mac;
    macidx += 1;
    mac = get_kb_item("SNMP/ifPhysAddress/" + macidx);
  }
  return macs;
}

##
# Parses MACs from various Host/raw_macs
#
# @remark uses KB "Host/raw_macs" (set by ssh_get_info.nasl)
#
# @return always a list of MACs (maybe empty)
##
function get_host_raw_macs()
{
  local_var macs = make_array();
  local_var buf  = get_kb_item("Host/raw_macs");
  if(empty_or_null(buf))
    return make_list();
  return split(buf, sep:',', keep:FALSE);
}

##
# Parses macs from the output of ifconfig
#
# @remark uses KB "Host/ifconfig" (set by ssh_get_info.nasl)
# 
# @return always a list of MACs (maybe empty)
##
function get_ifconfig_macs()
{
  local_var macs    = make_list();
  local_var buf     = get_kb_item("Host/ifconfig");
  local_var line    = "";
  local_var matches = NULL;
  local_var mac     = 0;
  local_var iface   = NULL;

  if(empty_or_null(buf))
    return make_list();

  buf = split(buf, sep:'\n', keep:FALSE);
  foreach line (buf)
  {
    matches = NULL;
    line = tolower(line);

    # Pull out the interface label if we're on that line
    matches = eregmatch(string:line, pattern:"^([a-z0-9]+:)");
    if(!empty_or_null(matches))
      iface = matches[1];

    # Skip all lines belonging to "virtual" interfaces
    # we only want hardware MACs
    if(iface =~ "^(vmnet[0-9]+|veth[0-9a-z]{6})")
      continue;

    # Regular ifconfig macs
    matches = eregmatch(string:line, pattern:"(hwaddr|ether) ("+IFCONFIG_MAC_RGX+")");
    # Now try solaris ifconfig macs
    if(empty_or_null(matches))
      matches = eregmatch(string:line, pattern:"(hwaddr|ether) ("+SOLARIS_MAC_RGX+")");
    # Add parsed mac
    if(!empty_or_null(matches))
        macs[mac++] = matches[2];
  }
  return macs;
}

##
# Main plug in code
##

# Make one big list of MACs form various sources
current_mac = "";
raw_macs = make_list();
raw_macs = make_list(get_host_raw_macs(), raw_macs);
raw_macs = make_list(get_ifconfig_macs(), raw_macs);
raw_macs = make_list(get_snmp_macs(), raw_macs);
current_mac = get_kb_item("SMB/mac_addr"); # From netbios_name_get.nasl
if(!isnull(current_mac))
  raw_macs = make_list(current_mac, raw_macs);
current_mac = get_kb_item("ARP/mac_addr"); # From bad_vlan.nasl
if(!isnull(current_mac))
  raw_macs = make_list(current_mac, raw_macs);

# Normalize MACs and ensure uniqueness
unique_macs = make_array();
normalized = "";
foreach current_mac (raw_macs)
{
  normalized = validate_and_normalize_mac(current_mac);
  if(normalized)
    unique_macs[normalized] = current_mac;
}

unique_macs = keys(unique_macs);
unique_macs = join(unique_macs, sep:'\n');
if(len(unique_macs) > 0)
{
  replace_kb_item(name:"Host/mac_addrs", value:unique_macs);
  report_xml_tag(tag:"mac-address", value:unique_macs);
}
