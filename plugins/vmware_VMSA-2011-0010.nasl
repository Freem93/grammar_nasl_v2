#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0010. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(55747);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/10/18 14:03:59 $");

  script_cve_id("CVE-2010-0296", "CVE-2011-0536", "CVE-2011-0997", "CVE-2011-1071", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-1659");
  script_bugtraq_id(44154, 46563, 47176, 47370);
  script_osvdb_id(65078, 68721, 71493, 72796, 73407, 75261);
  script_xref(name:"VMSA", value:"2011-0010");
  script_xref(name:"IAVA", value:"2011-A-0108");

  script_name(english:"VMSA-2011-0010 : VMware ESX third-party updates for Service Console packages glibc and dhcp");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESX host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console update for DHCP

    The DHCP client daemon, dhclient, does not properly sanatize
    certain options in DHCP server replies. An attacker could send a
    specially crafted DHCP server reply, that is saved on
    the client system and evaluated by a process that assumes the
    option is trusted. This could lead to arbitrary code execution
    with the privileges of the evaluating process.

    The Common Vulnerabilities and Exposures project (cve.mitre.org)
    has assigned the name CVE-2011-0997 to this issue.

b. Service Console update for glibc

    This patch updates the glibc package for ESX service console to
    glibc-2.5-58.7602.vmw. This fixes multiple security issues in
    glibc, glibc-common and nscd including possible local privilege
    escalation.
 
    The Common Vulnerabilities and Exposures project (cve.mitre.org)
    has assigned the identifiers CVE-2010-0296, CVE-2011-0536,
    CVE-2011-1095, CVE-2011-1071, CVE-2011-1658 and CVE-2011-1659 to
    these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000163.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/01");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2011-07-28");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201203405-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110406-SG",
    patch_updates : make_list("ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110408-SG",
    patch_updates : make_list("ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201107405-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201107406-SG",
    patch_updates : make_list("ESX410-201208104-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
