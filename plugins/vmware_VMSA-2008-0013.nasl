#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0013. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40381);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2006-3738", "CVE-2007-3108", "CVE-2007-5135", "CVE-2008-0960", "CVE-2008-1927", "CVE-2008-2292");
  script_bugtraq_id(25831, 28928, 29212, 29623);
  script_osvdb_id(29262, 37055, 44588, 45136, 46059, 46060, 46086, 46088, 46102, 46276, 46669);
  script_xref(name:"VMSA", value:"2008-0013");

  script_name(english:"VMSA-2008-0013 : Updated ESX packages for OpenSSL, net-snmp, perl");
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
"I Security Issues

  a. OpenSSL Binaries Updated

  This fix updates the third-party OpenSSL library.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2007-3108 and CVE-2007-5135 to the issues
  addressed by this update.

II Service Console rpm updates

  a. net-snmp Security update

  This fix upgrades the service console rpm for net-snmp to version
  net-snmp-5.0.9-2.30E.24.
 
  Note: this update is relevant for ESX 3.0.3. The initial advisory
  incorrectly stated that this update was present in ESX 3.0.3
  when it was released on August 8, 2008.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2008-2292 and CVE-2008-0960 to the issues
  addressed in net-snmp-5.0.9-2.30E.24.

  b. perl Security update

  This fix upgrades the service console rpm for perl to version
  perl-5.8.0-98.EL3.

  Note: this update is relevant for ESX 3.0.3. The initial advisory
  incorrectly stated that this update was present in ESX 3.0.3
  when it was released on August 8, 2008.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2008-1927 to the issue addressed in
  perl-5.8.0-98.EL3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000036.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 189, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
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


init_esx_check(date:"2008-08-12");
flag = 0;


if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1005115")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1006030")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1006355")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1005116")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006031")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006037")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200808401-SG",
    patch_updates : make_list("ESX303-201002202-UG", "ESX303-Update01")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200808402-SG",
    patch_updates : make_list("ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200808405-SG",
    patch_updates : make_list("ESX350-201002401-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200808406-SG",
    patch_updates : make_list("ESX350-201008412-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
