#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(47864);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/02/11 17:01:24 $");

 script_name(english:"Cisco IOS Version");
 script_summary(english:"Obtains the version of the remote IOS via SSH or SNMP.");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the IOS version number of the remote Cisco
device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running IOS, an operating system for Cisco routers.

It is possible to read the IOS version number by connecting to the
router via SSH or by using SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl", "cisco_default_pw.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc");
 script_exclude_keys("Host/Cisco/IOS-XR", "Host/Cisco/IOS-XE");

 exit(0);
}

include("global_settings.inc");

function test(s, ssh)
{
  local_var v, l, ver, image, model;
  local_var os, type;
  local_var report;

  if (! s) return s;

  l = egrep(string: s, pattern: "^Cisco IOS Software");
  if (! l && "Cisco Internetwork Operating System Software" >< s)
  {
    l = egrep(string: s, pattern: "^IOS \(tm\) [^.]+ Software");
  }
  if (! l) return s;
  v = eregmatch(string: s, pattern: "Version +([0-9]+\.[0-9]+[^ ,]+),");
  if (isnull(v)) return s;
  ver = v[1];
  set_kb_item(name:"Host/Cisco/IOS/Version", value: ver);
  report = '\n  IOS version : ' + ver;

  type = "router";

  model = eregmatch(string: s, pattern: "cisco ([^\(]+) \([^\)]+\) processor");
  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/IOS/Model", value : model[1]);

  image = eregmatch(string: l, pattern: "\(([^)]+)\), *Version");

  if (!isnull(image))
  {
    image = image[1];
    set_kb_item(name:"Host/Cisco/IOS/Image", value: image);

    image = split(image, sep:'-', keep:FALSE);
    if (max_index(image) == 3)
    {
      set_kb_item(name:"Host/Cisco/IOS/Platform", value: image[0]);
      set_kb_item(name:"Host/Cisco/IOS/FeatureSet", value: image[1]);
      set_kb_item(name:"Host/Cisco/IOS/ImageExecutionLocation", value: image[2]);

      report += '\n  Platform : ' + image[0] +
                '\n  Feature set : ' + image[1] +
                '\n  Image execution location : ' + image[2];
      if (ereg(pattern:"^C12[0-9]0", string:image[0])) type = "wireless-access-point";
    }
    else report += '\n  Image : ' + image;
  }
  report += '\n';

  if ( ssh == TRUE )
  {
   os = "CISCO IOS " + ver;
   set_kb_item(name:"Host/OS/CiscoShell", value:os);
   set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:100);
   set_kb_item(name:"Host/OS/CiscoShell/Type", value:type);
  }

  if (report_verbosity > 0) security_note(port:0, extra:report);
  else security_note(0);

  if ( report_paranoia > 1 || get_kb_item("Settings/PCI_DSS")) rm_kb_item(name:"Host/local_checks_enabled");

  exit(0);
}

# 1. SSH

# ios = get_kb_item("Host/Cisco/IOS");
showver = get_kb_item("Host/Cisco/show_ver");

test(s: showver, ssh:1);

# 2. SNMP

desc = get_kb_item("SNMP/sysDesc");
# oid = get_kb_item("SNMP/OID");
# contact = get_kb_item("SNMP/sysContact");
# location = get_kb_item("SNMP/sysLocation");

test(s: desc);

exit(1, "The IOS version is not available.");
