#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2017-0006. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(99102);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id("CVE-2017-4902", "CVE-2017-4903", "CVE-2017-4904", "CVE-2017-4905");
  script_osvdb_id(154017, 154021, 154022, 154594);
  script_xref(name:"VMSA", value:"2017-0006");
  script_xref(name:"IAVA", value:"2017-A-0086");
  script_xref(name:"IAVB", value:"2017-B-0036");
  script_xref(name:"IAVB", value:"2017-B-0037");
  script_xref(name:"IAVB", value:"2017-B-0038");

  script_name(english:"VMSA-2017-0006 : VMware ESXi, Workstation and Fusion updates address critical and moderate security issues");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. ESXi, Workstation, Fusion SVGA memory corruption

ESXi, Workstation, Fusion have a heap buffer overflow and
uninitialized stack memory usage in SVGA. These issues may allow
a guest to execute code on the host.

VMware would like to thank ZDI and Team 360 Security from Qihoo for
reporting these issues to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifiers CVE-2017-4902 (heap issue) and
CVE-2017-4903 (stack issue) to these issues.

Note: ESXi 6.0 is affected by CVE-2017-4903 but not by CVE-2017-4902.

b. ESXi, Workstation, Fusion XHCI uninitialized memory usage

The ESXi, Workstation, and Fusion XHCI controller has uninitialized
memory usage. This issue may allow a guest to execute code on
the host. The issue is reduced to a Denial of Service of the guest
on ESXi 5.5.

VMware would like to thank ZDI and Team Sniper from Tencent Security
for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4904 to this issue.

c. ESXi, Workstation, Fusion uninitialized memory usage

ESXi, Workstation, and Fusion have uninitialized memory usage. This
issue may lead to an information leak.

VMware would like to thank ZDI and Team Sniper from Tencent Security
for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4905 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2017/000373.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2017-03-28");
flag = 0;


if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.58.5224934")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.58.5224737")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.58.5224738")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-0.15.5224529")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-0.15.5224529")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-0.15.5224529")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
