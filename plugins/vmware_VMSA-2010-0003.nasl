#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0003. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(44642);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/18 01:35:31 $");

  script_cve_id("CVE-2009-1887");
  script_osvdb_id(49524, 56459);
  script_xref(name:"VMSA", value:"2010-0003");

  script_name(english:"VMSA-2010-0003 : ESX Service Console update for net-snmp");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console package net-snmp updated

   This patch updates the service console package for net-snmp,
   net-snmp-utils, and net-snmp-libs to version
   net-snmp-5.0.9-2.30E.28. This net-snmp update fixes a divide-by-
   zero flaw in the snmpd daemon. A remote attacker could issue a
   specially crafted GETBULK request that could cause the snmpd daemon
   to fail.

   This vulnerability was introduced by an incorrect fix for
   CVE-2008-4309.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org) has
   assigned the name CVE-2009-1887 to this issue.

   Note: After installing the previous patch for net-snmp
   (ESX350-200901409-SG), running the snmpbulkwalk command with the
   parameter -CnX results in no output, and the snmpd daemon stops."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000084.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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


init_esx_check(date:"2010-02-16");
flag = 0;


if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201002202-SG")) flag++;

if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201002401-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
