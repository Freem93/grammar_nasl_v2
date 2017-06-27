#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54996);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2011-1787", "CVE-2011-2145", "CVE-2011-2146");
  script_bugtraq_id(48098);
  script_osvdb_id(73240, 73241, 73242);
  script_xref(name:"VMSA", value:"2011-0009");
  script_xref(name:"IAVA", value:"2011-A-0075");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2011-0009)");
  script_summary(english:"Checks vulnerable versions of VMware products");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A VMware product (Player or Workstation) detected on the remote host
has multiple vulnerabilities in the Host Guest File System :

  - An attacker with access to a Guest operating system can
    determine if a path exists in the Host filesystem and
    whether it's a file or a directory regardless of
    permissions. (CVE-2011-2146)

  - A race condition in mount.vmhgfs may allow an attacker
    with access to a Guest to mount on arbitrary directories
    in the Guest filesystem and escalate their privileges if
    they can control the contents of the mounted directory.
    (CVE-2011-1787)

  - A procedural error allows an attacker with access to a
    Solaris or FreeBSD Guest operating system to gain write
    access to an arbitrary file in the Guest filesystem.
    (CVE-2011-2145)

These vulnerabilities only affect non-Windows guest operating systems."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.vmware.com/security/advisories/VMSA-2011-0009.html");
  script_set_attribute(attribute:"see_also",value:"http://lists.vmware.com/pipermail/security-announce/2011/000141.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to :

  - VMware Workstation 7.1.4 or later.
  - VMware Player 3.1.4 or later.

In addition to patching, VMware Tools must be updated on all non-
Windows guest VMs in order to completely mitigate certain
vulnerabilities.  Refer to the VMware advisory for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/06/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("VMware/Workstation/Version", "VMware/Player/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


port = kb_smb_transport();
report = "";

# Check for VMware Workstation
version = get_kb_item("VMware/Workstation/Version");
if (version)
{
  fix = '7.1.4';

  if (version =~ '^7\\.1' && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    report += 
      '\n  Product           : VMware Workstation'+
      '\n  Installed version : '+version+
      '\n  Fixed version     : ' + fix + '\n';
  }
}

# Check for VMware Player
version = get_kb_item("VMware/Player/Version");
if (version)
{
  fix = '3.1.4';

  if (version =~ '^3\\.1' && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    report +=
      '\n  Product           : VMware Player'+
      '\n  Installed version : '+version+
      '\n  Fixed version     : ' + fix + '\n';
  }
}

if (!report) exit(0, "The host is not affected.");

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole();
