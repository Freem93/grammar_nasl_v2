#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(71430);
 script_version("$Revision: 1.4 $");
 script_cvs_date("$Date: 2016/05/17 17:47:58 $");

 script_name(english:"Cisco IOS XR Version");
 script_summary(english:"Obtains the version of the remote IOS XR.");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the IOS XR version number of the remote
Cisco device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running IOS XR, an operating system for high-end
carrier-grade Cisco routers. 

It is possible to read the IOS XR version number by connecting to the
router using SSH or SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl", "cisco_default_pw.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

function remove_leading_zero(s)
{
  local_var str, temp, parts, part;
  parts = split(s, sep:".", keep:FALSE);
  foreach part (parts)
  {
    temp = ereg_replace(pattern:"^0*", replace:"", string:part);
    if (temp == "") temp = "0";
    if (str) str = str + "." + temp;
    else str = temp;
  }
  return str;
}

function test(s, ssh)
{
  local_var v, l, m, ver, image;
  local_var     os, type, source;
  local_var matches, model, report;

  if (!s) return;

  # SSH / SNMP detection
  # nb: see "IOS XR Numbering" section in
  #     http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6968/ps6350/whitepaper_C11-719867.html
  l = egrep(string:s, pattern:"^.* IOS[ -]XR Software.*Version [0-9]+\.[0-9.]+");
  if (!strlen(l)) return;

  v = eregmatch(string:l, pattern:"(?: \(Cisco ([^)]+)\))?, *Version +([0-9]+\.[0-9.]+)");
  if (isnull(v)) return;

  ver = chomp(v[2]);

  # Remove leading 0's from the version
  ver = remove_leading_zero(s:ver);

  set_kb_item(name:"Host/Cisco/IOS-XR/Version", value:ver);

  # SSH parse model
  if (ssh)
  {
    matches = eregmatch(string:l, pattern:"^cisco ([^(]+) \([^)]+\) processor");
    if (matches)
      model = matches[1];
    else
    {
      # Try looking globally on the configuration
      matches = eregmatch(string:s, pattern:"(^|\r?\n)cisco ([^(]+) \([^)]+\) processor");
      if (matches)
        model = matches[2];
    }
  }
  # SNMP parse model
  else if (!isnull(v[1]))
    model = v[1];

  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/IOS-XR/Model", value:model);

  type   = "router";
  source = "SNMP";

  if (ssh)
  {
    source = "SSH";
    os = "Cisco IOS XR " + ver;
    set_kb_item(name:"Host/OS/CiscoShell", value:os);
    set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:100);
    set_kb_item(name:"Host/OS/CiscoShell/Type", value:type);
  }

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;

  if (!isnull(model))
    report += '\n  Model   : ' + model;

  report += '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
  exit(0);
}

# 1. SSH
showver = get_kb_item("Host/Cisco/show_ver");
if (showver)
  test(s:showver, ssh:TRUE);

# 2. SNMP
desc = get_kb_item("SNMP/sysDesc");
if (desc)
  test(s:desc);

audit(AUDIT_UNKNOWN_DEVICE_VER, "Cisco IOS XR");
