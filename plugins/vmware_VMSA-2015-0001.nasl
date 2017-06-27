#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2015-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(81079);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568", "CVE-2014-3660", "CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044");
  script_bugtraq_id(70574, 70584, 70585, 70586, 70644, 72336, 72337, 72338);
  script_osvdb_id(113251, 113373, 113374, 113377, 113389, 116957);
  script_xref(name:"VMSA", value:"2015-0001");
  script_xref(name:"IAVB", value:"2015-B-0012");
  script_xref(name:"IAVB", value:"2015-B-0013");
  script_xref(name:"IAVB", value:"2015-B-0014");

  script_name(english:"VMSA-2015-0001 : VMware vCenter Server, ESXi, Workstation, Player, and Fusion updates address security issues (POODLE)");
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
"a. VMware ESXi, Workstation, Player, and Fusion host privilege
   escalation vulnerability

   VMware ESXi, Workstation, Player and Fusion contain an arbitrary
   file write issue. Exploitation this issue may allow for privilege
   escalation on the host.

   The vulnerability does not allow for privilege escalation from
   the guest Operating System to the host or vice-versa. This means
   that host memory can not be manipulated from the Guest Operating
   System.

   Mitigation

   For ESXi to be affected, permissions must have been added to ESXi
   (or a vCenter Server managing it) for a virtual machine
   administrator role or greater.

   VMware would like to thank Shanon Olsson for reporting this issue to
   us through JPCERT.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifier CVE-2014-8370 to this issue.

b. VMware Workstation, Player, and Fusion Denial of Service
   vulnerability

   VMware Workstation, Player, and Fusion contain an input
   validation issue in the Host Guest File System (HGFS).
   This issue may allow for a Denial of Service of the Guest
   Operating system.

   VMware would like to thank Peter Kamensky from Digital
   Security for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifier CVE-2015-1043 to this issue.

c. VMware ESXi, Workstation, and Player Denial of Service
   vulnerability

   VMware ESXi, Workstation, and Player contain an input
   validation issue in VMware Authorization process (vmware-authd).
   This issue may allow for a Denial of Service of the host. On
   VMware ESXi and on Workstation running on Linux the Denial of
   Service would be partial.

   VMware would like to thank Dmitry Yudin @ret5et for reporting
   this issue to us through HP's Zero Day Initiative.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifier CVE-2015-1044 to this issue.

d. Update to VMware vCenter Server and ESXi for OpenSSL 1.0.1
   and 0.9.8 package

   The OpenSSL library is updated to version 1.0.1j or 0.9.8zc
   to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2014-3513, CVE-2014-3567,
   CVE-2014-3566 (&igrave;POODLE&icirc;) and CVE-2014-3568 to these issues.

e. Update to ESXi libxml2 package

   The libxml2 library is updated to version libxml2-2.7.6-17
   to resolve a security issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2014-3660 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2015/000290.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2015-01-27");
flag = 0;


if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-3.47.1749766")) flag++;
if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-3.65.2486588")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-2.27.1743201")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-3.55.2583090")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-tboot:5.1.0-2.23.1483097")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:misc-drivers:5.1.0-2.23.1483097")) flag++;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-2.51.2352327")) flag++;
if (esx_check(ver:"ESXi 5.5", vib:"VMware:tools-light:5.5.0-0.14.1598313")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
