#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33276);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/26 18:40:45 $");

  script_name(english:"Enumerate MAC Addresses via SSH");
  script_summary(english:"Uses the result of 'ifconfig -a' or 'ip addr show'.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate MAC addresses on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate MAC addresses by connecting to the remote
host via SSH with the supplied credentials.");
  script_set_attribute(attribute:"solution", value:
"Disable any unused interfaces.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");
  script_require_ports("Host/ifconfig", "Host/netstat-ian", "Host/lanscan-ai", "Host/nwmgr");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

devs = make_array();    # for building a string
unique_macs = make_array();
ordered_macs = make_list();

uname = get_kb_item_or_exit("Host/uname");
# For AIX hosts
# MAC addresses cannot be obtained using 'ifconfig'
if ('AIX' >< uname)
{
  netstat = get_kb_item_or_exit("Host/netstat-ian");
  if (!isnull(netstat))
  {
    # netstat regex
    # en0   1500  link#2      0.11.25.7e.67.f2  3691380     0   841820     4     0
    netstat_pat = "^([^\s]+)\s+[0-9]+\s+[^\s]+\s+([0-9a-fA-F.:-]+)(?:\s+[0-9]+)+";
    foreach line (split(netstat, keep:FALSE))
    {
      match = eregmatch(pattern:netstat_pat, string:line);
      if (!isnull(match))
      {
        iface_name = match[1];
        addr = match[2]; # can be IP or MAC

        sep = '';
        # only want MAC addr
        if (':' >< addr) sep = ':';
        else if ('.' >< addr) sep = '.';
        else if ('-' >< addr) sep = '-';
        else continue; # not a mac

        addr_parts = split(addr, sep:sep, keep:FALSE);
        if (len(addr_parts) != 6) continue;
        # zero pad
        for (i = 0; i < len(addr_parts); i++)
          if (len(addr_parts[i]) == 1) addr_parts[i] = "0"+addr_parts[i];

        mac_addr = join(addr_parts, sep:':');
        set_kb_item(name:"Host/ifconfig/mac_addr", value:mac_addr);

        if (!devs[mac_addr]) devs[mac_addr] = make_list(iface_name);
        else devs[mac_addr] = make_list(devs[mac_addr], iface_name);
        unique_macs[mac_addr] = mac_addr;
      }
    }
  }
}
else if ('HP-UX' >< uname)
{
  nwmgr = get_kb_item("Host/nwmgr");
  lanscan = NULL;
  if (!isnull(nwmgr))
  {
    # lan0           UP        0x00226494A59B igelan   1000Base-T 
    # transform nwmgr output into lanscan format
    nwmgr_regex = "^([^\s]+)\s+[A-Za-z]+\s+(0x[0-9A-F]+)\s+.*$";
    lanscan = "";
    foreach line (split(nwmgr, keep:FALSE))
    {
      res = ereg_replace(string:line, pattern:nwmgr_regex, replace:'\\2 \\1 dummy\n');
      if (!isnull(res) && res != line) lanscan += res;
    }
  }

  # check lanscan output if needed
  if (empty_or_null(lanscan)) lanscan = get_kb_item("Host/lanscan-ai");
  if (empty_or_null(lanscan)) exit(0, "No interfaces found for HP-UX host.");

  # lanscan regex
  # 0x00226494A59B lan0 snap0
  lanscan_pat = "^0x([0-9A-F]+)\s+([^\s]+)\s+.*$";
  foreach line (split(lanscan, keep:FALSE))
  {
    match = eregmatch(pattern:lanscan_pat, string:line);
    if (!isnull(match))
    {
      temp_mac = '';
      mac_addr = match[1];
      iface_name = match[2];

      if (empty_or_null(mac_addr) || empty_or_null(iface_name)) continue;

      # add colons to mac address
      # but not after the last byte
      if (len(mac_addr) == 12 &&
          (
           ':' >!< mac_addr &&
           '.' >!< mac_addr &&
           '-' >!< mac_addr
          )
      )
      {
        i = 0;
        while(i < len(mac_addr)-2)
        {
          temp_mac += mac_addr[i] + mac_addr[i+1] + ':';
          i += 2;
        }
        temp_mac += mac_addr[i] + mac_addr[i+1];
        mac_addr = temp_mac;
      }

      set_kb_item(name:"Host/ifconfig/mac_addr", value:mac_addr);

      if (!devs[mac_addr]) devs[mac_addr] = make_list(iface_name);
      else devs[mac_addr] = make_list(devs[mac_addr], iface_name);
      unique_macs[mac_addr] = mac_addr;
    }
  }
}
else
{
  ifconfig = get_kb_item_or_exit("Host/ifconfig");
  pat_dev = "^(\d: )?([a-z]+[a-z0-9]+([\-:][a-z0-9]+)?)[: ].*";
  pat_mac = ".*(HWaddr|ether) ?([0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}).*";

  # Gather information.                                                                                                                                                                                                                                     
  dev = NULL;
  target_ip = get_host_ip();
  target_mac = NULL;
  mac = NULL;

  foreach line (split(ifconfig, keep:FALSE))
  {
    if (line =~ pat_dev)
    {
      dev = ereg_replace(pattern:pat_dev, replace:"\2", string:line);
      if (dev == line) dev = NULL;
      mac = "";
    }
    if ("HWaddr " >< line || "ether " >< line)
    {
      mac = ereg_replace(pattern:pat_mac, replace:"\2", string:line);
      if (mac != line && dev)
      {
        # MACs can be represented like:
        #   12-34-56-78-9a-bc
        #   1234.5678.9abc
        #   12:34:56:78:9a:bc
        # bytes < 0x10 must be zero padded. the following MAC is not valid:
        #   1:23:4:56:7:89
        # Solaris (possibly other OSes?) report MACs like this. They should be normalized like:
        #   01:23:04:56:07:89
        if (':' >< mac && strlen(mac) != 17)
        {
          mac_bytes = split(mac, sep:':', keep:FALSE);
          for (i = 0; i < max_index(mac_bytes); i++)
          {
            if (strlen(mac_bytes[i]) == 1)
              mac_bytes[i] = strcat('0', mac_bytes[i]);
          }

          mac = join(mac_bytes, sep:':');
        }

        unique_macs[mac] = mac;

        set_kb_item(name:"Host/ifconfig/mac_addr", value:mac); # name = mac_addr (singular)
        if (!devs[mac]) devs[mac] = make_list(dev);
        else devs[mac] = make_list(devs[mac], dev);
      }
    }
    if ("inet" >< line)
    {
      if ("inet6" >< line)
      {
        addr = ereg_replace(pattern:".*inet6( addr:)? ([0-9a-f:]*).*", string:line, replace:"\2");
      }
      else
      {
        addr = ereg_replace(pattern:".*inet( addr:)? ?([0-9.]+).*", string:line, replace:"\2");
      }
      if (addr != line && addr == target_ip && mac)
      {
        target_mac = mac;
        if (defined_func("report_xml_tag")) report_xml_tag(tag:"mac-address", value:mac);
      }
    }
  }
}

if (max_index(keys(devs)) == 0) exit(0, 'Unable to parse any MAC addresses.');

# Issue report.
info = make_list();

tgt_str = NULL;
foreach mac (unique_macs)
{
  s = "";
  if (len(devs[mac]) > 1) s = "s";
  dev_str = devs[mac][0];

  # virtual devices share a mac address with a physical device
  # a physical device will have the shortest device name
  # e.g. eth0... eth0:0
  shortest = len(devs[mac][0]);
  physical = 0; # index of device

  for (i = 1; i < len(devs[mac]); i++)
  {
    dev_str += ' & ' + devs[mac][i];
    cur_len = len(devs[mac][i]);
    if (cur_len < shortest)
    {
      shortest = cur_len;
      physical = i;
    }
  }

  for (i = 0; i < len(devs[mac]); i++)
  {
    iface_name = devs[mac][i];
    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/mac", value:mac);

    # set 'virtual' kb item
    if (i != physical)
      set_kb_item(name:"Host/iface/"+iface_name+"/virtual", value:TRUE);
  }

  # set 'aliased' kb item if virtual devices exist
  aliased = len(devs[mac]) > 1;
  if (aliased)
    set_kb_item(name:"Host/iface/"+devs[mac][physical]+"/aliased", value:TRUE);

  info_str = '  - ' + mac + ' (interface' + s + ' ' + dev_str + ')';

  if(mac == target_mac) tgt_str = info_str;
  else
  {
    info = make_list(info_str, info);
    ordered_macs = make_list(mac, ordered_macs);
  }
}

if(!empty_or_null(tgt_str)){
  info = make_list(tgt_str, info);
  ordered_macs = make_list(target_mac, ordered_macs);
}

info = join(info,sep:'\n') + '\n';
ordered_macs = join(ordered_macs,sep:'\n');
set_kb_item(name:"Host/ifconfig/mac_addrs", value:ordered_macs);  # name = mac_addrs (plural)

if (report_verbosity > 0 && info)
{
  if (max_index(keys(devs)) == 1) report = "address exists";
  else report = "addresses exist";
  report = '\n' + 'The following MAC ' + report + ' on the remote host :' +
           '\n' +
           '\n' + info;
  security_note(port:0, extra:report);
}
else security_note(0);
