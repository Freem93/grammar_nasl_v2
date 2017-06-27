#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(66696);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2017/03/23 20:49:48 $");

 script_name(english:"Cisco NX-OS Version");
 script_summary(english:"Obtains the version of the remote NX-OS.");

 script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the NX-OS version of the remote Cisco device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running NX-OS, an operating system for Cisco
switches.

It is possible to read the NX-OS version and Model either through SNMP
or by connecting to the switch using SSH.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl", "cisco_default_pw.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");

##
# Saves the provided NXOS version number in the KB, generates plugin output,
# and exits.  If a model number is provided it is also saved in
# the KB and reported, but a model number is not required.
#
# @anonparam ver NXOS version number
# @anonparam device NXOS device type
# @anonparam model NXOS model number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, device, model, serial, source)
{
  local_var report, os;

  set_kb_item(name:"Host/Cisco/NX-OS/Device", value:device);

  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/NX-OS/Model", value:model);

  set_kb_item(name:"Host/Cisco/NX-OS/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/NX-OS", value:TRUE);

  if ( source == "SSH" )
  {
   os = "CISCO NX-OS " + ver;
   set_kb_item(name:"Host/OS/CiscoShell", value:os);
   set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:100);
   set_kb_item(name:"Host/OS/CiscoShell/Type", value:"switch");
  }

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;
  if (!isnull(device))
    report += '\n  Device  : ' + device;
  if (!isnull(model))
    report += '\n  Model   : ' + model;
  report += '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
  exit(0);
}

version = NULL;
device = NULL;
model = NULL;

# 1. SSH
ips_ssh = get_kb_item("Host/Cisco/show_ver");
if (ips_ssh)
{
  if ("Cisco Nexus Operating System (NX-OS) Software" >< ips_ssh)
  {
    version = eregmatch(string:ips_ssh, pattern:"NXOS:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*", icase:TRUE);
    if (isnull(version))
      version = eregmatch(string:ips_ssh, pattern:"[Ss]ystem:?\s+[Vv]ersion:?\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*");

    if (!isnull(version))
    {
      # Check if it's a UCS device
      # this can be expanded when we know more about Cisco UCS products
      ssh_port = get_service(svc:'ssh', default:22);
      banner = get_kb_item('SSH/textbanner/'+ssh_port);
      # e.g. textbanner = Cisco UCS 6200 Series Fabric Interconnect\n 
      if (!isnull(banner))
      {
        banner = chomp(banner);
        pat = "^Cisco UCS (\S+ Series) Fabric Interconnect$";
        model = pregmatch(string:banner, pattern:pat, icase:TRUE);
        if (!isnull(model)) device = 'Cisco UCS Fabric Interconnect';
      }

      if (isnull(model))
      {
        if ('MDS' >< ips_ssh)
        {
          device = 'MDS';

          model = eregmatch(string:ips_ssh, pattern:"MDS\s*\d+\s+[cC]([^\r\n\s]+)[^\r\n]*\s+Chassis");
          if (isnull(model))
            model = eregmatch(string:ips_ssh, pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
        else
        {
          device = 'Nexus';

          model = eregmatch(string:ips_ssh, pattern:"[Nn]exus\s*\d+\s+[cC]([^\r\n\s]+)[^\r\n]*\s+[Cc]hassis");
          if (isnull(model))
            model = eregmatch(string:ips_ssh, pattern:"[Nn]exus\s*([^\r\n\s]+)[^\r\n]*\s+[Cc]hassis");
        }
      }

      report_and_exit(ver:version[1], device:device,  model:model[1], source:'SSH');
    }
  }
}

# 2. SNMP
ips_snmp = get_kb_item("SNMP/sysDesc");
if (ips_snmp)
{
  community = get_kb_item("SNMP/community");
  if ( (community) && (!model) )
  {
    port = get_kb_item("SNMP/port");
    if(!port)port = 161;
    if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    soc = open_sock_udp(port);
    if (soc)
    {
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
      if ( (txt) && ('NX-OS' >< txt) )
      {
        # get version
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.9.22");
        if (txt) version = txt;

        # get model
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.149");
        if (txt && 'MDS' >< txt)
        {
          device = 'MDS';

          model = eregmatch(string:txt, pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
        if (txt && 'Nexus' >< txt)
        {
          device = 'Nexus';

          model = eregmatch(string:txt, pattern:"Nexus\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
      }
    }
  }

  if (!isnull(version))
  {
    report_and_exit(ver:version, device:device, model:model[1], source:'SNMP');
    # never reached
  }
}

failed_methods = make_list();
if (ips_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (ips_snmp)
  failed_methods = make_list(failed_methods, 'SNMP');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine Cisco NX-OS version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The Cisco NX-OS version is not available (the remote host may not be Cisco NXOS).');
