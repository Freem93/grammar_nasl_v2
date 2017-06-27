#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(51422);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2014/11/14 12:03:07 $");

  script_cve_id("CVE-2010-0211", "CVE-2010-0212", "CVE-2010-2956", "CVE-2010-3847", "CVE-2010-3856", "CVE-2011-0536");
  script_bugtraq_id(41770, 43019, 44154, 44347);
  script_osvdb_id(66469, 66470, 67842, 68721, 68920);
  script_xref(name:"VMSA", value:"2011-0001");

  script_name(english:"VMSA-2011-0001 : VMware ESX third-party updates for Service Console packages glibc, sudo, and openldap");
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
"a. Service Console update for glibc

   The service console packages glibc, glibc-common, and nscd are each
   updated to version 2.5-34.4908.vmw.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-3847 and CVE-2010-3856 to the issues
   addressed in this update.

b. Service Console update for sudo

   The service console package sudo is updated to version
   1.7.2p1-8.el5_5.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-2956 to the issue addressed in this
   update.

c. Service Console update for openldap

   The service console package openldap is updated to version
   2.3.43-12.el5_5.1.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-0211 and CVE-2010-0212 to the issues
   addressed in this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000150.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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


init_esx_check(date:"2011-01-04");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201101404-SG",
    patch_updates : make_list("ESX400-201305402-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201101405-SG",
    patch_updates : make_list("ESX400-201110408-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201101226-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201107406-SG", "ESX410-201208104-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201104404-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
