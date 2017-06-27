#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40387);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-4225", "CVE-2008-4226", "CVE-2008-4309", "CVE-2008-4914");
  script_bugtraq_id(32020, 32326, 32331);
  script_osvdb_id(49524, 49992, 49993, 52705);
  script_xref(name:"VMSA", value:"2009-0001");

  script_name(english:"VMSA-2009-0001 : ESX patches address an issue loading corrupt virtual disks and update Service Console packages");
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
"a. Loading a corrupt delta disk may cause ESX to crash

   If the VMDK delta disk of a snapshot is corrupt, an ESX host might
   crash when the corrupted disk is loaded.  VMDK delta files exist
   for virtual machines with one or more snapshots. This change ensures
   that a corrupt VMDK delta file cannot be used to crash ESX hosts.

   A corrupt VMDK delta disk, or virtual machine would have to be loaded
   by an administrator.

   VMware would like to thank Craig Marshall for reporting this issue.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2008-4914 to this issue.

b. Updated Service Console package net-snmp

   Net-SNMP is an implementation of the Simple Network Management
   Protocol (SNMP). SNMP is used by network management systems to
   monitor hosts.

   A denial-of-service flaw was found in the way Net-SNMP processes
   SNMP GETBULK requests. A remote attacker who issued a specially-
   crafted request could cause the snmpd server to crash.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2008-4309 to this issue.

c. Updated Service Console package libxml2

   An integer overflow flaw causing a heap-based buffer overflow was
   found in the libxml2 XML parser. If an application linked against
   libxml2 processed untrusted, malformed XML content, it could cause
   the application to crash or, possibly, execute arbitrary code.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org) has
   assigned the name CVE-2008-4226 to this issue.

   A denial of service flaw was discovered in the libxml2 XML parser.
   If an application linked against libxml2 processed untrusted,
   malformed XML content, it could cause the application to enter
   an infinite loop.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2008-4225 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000052.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/30");
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


init_esx_check(date:"2009-01-30");
flag = 0;


if (esx_check(ver:"ESX 2.5.5", patch:"12")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1007673")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1007674")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200901405-SG",
    patch_updates : make_list("ESX303-201002202-UG", "ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200901406-SG",
    patch_updates : make_list("ESX303-201002204-UG", "ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200901401-SG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-201006401-SG", "ESX350-201012401-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200901409-SG",
    patch_updates : make_list("ESX350-201002401-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200901410-SG",
    patch_updates : make_list("ESX350-201002407-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200901401-I-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
