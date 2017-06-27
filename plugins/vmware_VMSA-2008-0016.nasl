#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0016. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40383);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3109", "CVE-2008-3110", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114", "CVE-2008-3115", "CVE-2008-4278", "CVE-2008-4279");
  script_bugtraq_id(30140, 30141, 30142, 30143, 30146, 30147, 30148);
  script_osvdb_id(46955, 46956, 46957, 46958, 46959, 46960, 46961, 46962, 46963, 46964, 46965, 46966, 46967, 49089, 49090);
  script_xref(name:"VMSA", value:"2008-0016");

  script_name(english:"VMSA-2008-0016 : VMware Hosted products, VirtualCenter Update 3 and patches for ESX and ESXi resolve multiple security issues");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi / ESX host is missing one or more
security-related patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a.  Privilege escalation on 64-bit guest operating systems

  VMware products emulate hardware functions, like CPU, Memory, and
  IO.  

  A flaw in VMware's CPU hardware emulation could allow the
  virtual CPU to jump to an incorrect memory address. Exploitation of
  this issue on the guest operating system does not lead to a
  compromise of the host system but could lead to a privilege
  escalation on guest operating system.  An attacker would need to
  have a user account on the guest operating system.

  Affected
  64-bit Windows and 64-bit FreeBSD guest operating systems and
  possibly other 64-bit operating systems. The issue does not
  affect the 64-bit versions of Linux guest operating systems.

  VMware would like to thank Derek Soeder for discovering
  this issue and working with us on its remediation.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2008-4279 this issue.

 b. Update for VirtualCenter fixes a potential information disclosure

 This release resolves an issue where a user's password could be
 displayed in cleartext. When logging into VirtualCenter Server 2.0
 with Virtual Infrastructure Client 2.5, the user password might be
 displayed if it contains certain special characters. The dialog
 box displaying the password can appear in front or hidden behind
 other windows.

 To remediate this issue the VirtualCenter client installations must
 be updated after updating to VirtualCenter Update 3

 VMware would like to thank Mark Woollatt for reporting this issue
 to VMware.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the name CVE-2008-4278 to this issue.

 c. Update for VirtualCenter updates JRE to version 1.5.0_16

 Update for VirtualCenter updates the JRE package to version 1.5.0_16,
 which addresses multiple security issues that existed in the previous
 version of JRE.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the names CVE-2008-3103, CVE-2008-3104, CVE-2008-3105,
 CVE-2008-3106, CVE-2008-3107, CVE-2008-3108, CVE-2008-3109,
 CVE-2008-3110, CVE-2008-3111, CVE-2008-3112, CVE-2008-3113,
 CVE-2008-3114, CVE-2008-3115 to the security issues fixed in
 JRE 1.5.0_16."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000044.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(16, 20, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2008-10-03");
flag = 0;


if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1006678")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006361")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200809401-SG",
    patch_updates : make_list("ESX303-201002201-UG", "ESX303-Update01")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200809404-SG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-201006401-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200810215-UG",
    patch_updates : make_list("ESX350-201003403-SG", "ESX350-201203401-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200809401-I-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
