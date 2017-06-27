#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83729);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2015-3456");
  script_bugtraq_id(74640);
  script_osvdb_id(122072);
  script_xref(name:"IAVA", value:"2015-A-0112");

  script_name(english:"Oracle VM VirtualBox < 3.2.28 / 4.0.30 / 4.1.38 / 4.2.30 / 4.3.28 QEMU FDC Overflow RCE (VENOM)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox that is
prior to 3.2.28 / 4.0.30 / 4.1.38 / 4.2.30 / 4.3.28. It is, therefore
affected by a flaw in the Floppy Disk Controller (FDC) in the bundled
QEMU software due to an overflow condition in 'hw/block/fdc.c' when
handling certain commands. An attacker, with access to an account on
the guest operating system with privilege to access the FDC, can
exploit this flaw to execute arbitrary code in the context of the
hypervisor process on the host system.");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2015-3456-2542656.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bd5df81");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"see_also", value:"http://venom.crowdstrike.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Oracle VM VirtualBox to 3.2.28 / 4.0.30 / 4.1.38 / 4.2.30 /
4.3.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("VirtualBox/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('VirtualBox/Version');
path = get_kb_item_or_exit('SMB/VirtualBox/'+ver);

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Affected :
# 3.2.x < 3.2.28
# 4.0.x < 4.0.30
# 4.1.x < 4.1.38
# 4.2.x < 4.2.30
# 4.3.x < 4.3.28
if (major == 3 && minor == 2 && rev < 28) fix = '3.2.28';
else if (major == 4 && minor == 0 && rev < 30) fix = '4.0.30';
else if (major == 4 && minor == 1 && rev < 38) fix = '4.1.38';
else if (major == 4 && minor == 2 && rev < 30) fix = '4.2.30';
else if (major == 4 && minor == 3 && rev < 28) fix = '4.3.28';

if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Oracle VM VirtualBox', ver, path);
