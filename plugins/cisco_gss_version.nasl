#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(68960);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2013/07/18 21:39:00 $");

 script_name(english:"Cisco GSS Version");
 script_summary(english:"Obtains the version of the remote GSS appliance");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the GSS version number of the remote Cisco
appliance.");
 script_set_attribute(attribute:"description", value:
"The remote host is running GSS, an operating system for Cisco load
balancers. 

It is possible to read the GSS version number by connecting to the
router by SSH or by using SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:gss");

 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl", "cisco_default_pw.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc", "Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');
include('audit.inc');

function test(s, ssh)
{
  local_var	v, m, ver, image, model;
  local_var     os, type, txt;

  if (!s) return;

  # Global Site Selector (GSS)
  # Model Number: GSS-4491-k9
  # Copyright (c) 1999-2007 by Cisco Systems, Inc.
  # Version 2.0(1)

  # Make sure this looks like a Cisco GSS device
  v = eregmatch(string:s, pattern:"Version\s\s*([0-9\.\(\)]+)");
  if (isnull(v)) ver = "unknown";
  else ver = chomp(v[1]);

  m = eregmatch(string:s, pattern:"Model\s\s*Number\s*:\s\s*GSS\-([^-]+)");
  if (isnull(m)) model = "unknown";
  else model = chomp(m[1]);

  # only set the kb items if we were able to identify at least one of version and model
  if ( (ver == "unknown") && (model == "unknown") ) return;

  # only set the kb items if the do not exist or if they were set to "unknown"
  txt = get_kb_item("Host/Cisco/GSS/model");
  if ((!txt) || (txt == "unknown") ) set_kb_item(name:"Host/Cisco/GSS/model", value: model);
  txt = get_kb_item("Host/Cisco/GSS/Version");
  if ((!txt) || (txt == "unknown") ) set_kb_item(name:"Host/Cisco/GSS/Version", value: ver);

  type = "load balancer";

  if ( (ssh == TRUE) && (ver != "unknown") )
  {
   os = "CISCO GSS Version " + ver;
   set_kb_item(name:"Host/OS/CiscoShell", value:os);
   set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:100);
   set_kb_item(name:"Host/OS/CiscoShell/Type", value:type);
  }
  exit(0);
}

gss = FALSE;
# 1. SSH
showver = get_kb_item("Host/Cisco/show_ver");
if ('Model Number' >< showver && 'GSS' >< showver)
{
  gss = TRUE;
  test(s: showver, ssh:1);
}

# 2. TELNET
telnet_port = get_kb_item("Services/telnet");
if (!telnet_port) telnet_port = 23;

t_banner = get_telnet_banner(port:telnet_port);
if ('Model Number' >< t_banner && 'GSS' >< t_banner)
{
  gss = TRUE;
  test(s: t_banner);
}

if (!gss)
  audit(AUDIT_HOST_NOT, 'Cisco GSS');

exit(1, "The GSS version is not available.");
