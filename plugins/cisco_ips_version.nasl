#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(69102);
 script_version("$Revision: 1.1 $");
 script_cvs_date("$Date: 2013/07/29 19:57:51 $");

 script_name(english:"Cisco IPS Version");
 script_summary(english:"Obtains the version of the remote Cisco IPS device");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the Cisco IPS version number, model number,
and/or serial number of the remote Cisco IPS device.");
 script_set_attribute(attribute:"description", value:
"The remote host is a Cisco Intrusion Prevention System (IPS). 

It is possible to read the Cisco IPS version number, model number,
and/or serial number by connecting to the device via SSH or SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
# Saves the provided IPS version number in the KB, generates plugin output,
# and exits.  If a model or serial number is provided it is also saved in
# the KB and reported, but a model and serial number is not required.
#
# @anonparam ver IPS version number
# @anonparam model IPS model number
# @anonparam serial IPS serial number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, serial, source)
{
  local_var report, display_ver;

  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/IPS/Model", value:model);

  if (!isnull(serial))
    set_kb_item(name:"Host/Cisco/IPS/Serial", value:serial);

  set_kb_item(name:"Host/Cisco/IPS/Version", value:ver);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    if (!isnull(model))
      report += '\n  Model   : ' + model;
    if (!isnull(serial))
      report += '\n  Serial  : ' + serial;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
ips_ssh = get_kb_item("Host/Cisco/show_ver");
if (ips_ssh)
{
  version = eregmatch(string:ips_ssh, pattern:"Cisco\s+Intrusion\s+Prevention\s+System,\s+Version\s+([^\s\r\n]+)");
  model = eregmatch(string:ips_ssh, pattern:"Platform\s*:\s+([^\s\r\n]+)");
  serial = eregmatch(string:ips_ssh, pattern:"Serial\s+Number\s*:\s+([^\s\r\n]+)");

  if (!isnull(version))
  {
    report_and_exit(ver:version[1], model:model[1], serial:serial[1], source:'SSH');
    # never reached
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
      # Sanity Check. are we looking at a IPS device?
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.1");
      if ( (txt) && (txt =~ "IPS") )
      {
        # get version
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.10.1");
        if (txt) version = txt;

        # get model
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.13.1");
        if (txt) model = txt;

        # get serial
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.11.1");
        if (txt) serial = txt;
      }
    }
  }

  if (!isnull(version))
  {
    report_and_exit(ver:version, model:model, serial:serial, source:'SNMP');
    # never reached
  }
}

failed_methods = make_list();
if (ips_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (ips_snmp)
  failed_methods = make_list(failed_methods, 'SNMP');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine Cisco IPS version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The Cisco IPS version is not available (the remote host may not be Cisco IPS).');
