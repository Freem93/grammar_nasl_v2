#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0016. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(62944);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2011-4940", "CVE-2011-4944", "CVE-2012-0441", "CVE-2012-0876", "CVE-2012-1033", "CVE-2012-1148", "CVE-2012-1150", "CVE-2012-1667", "CVE-2012-3817", "CVE-2012-5703");
  script_bugtraq_id(51239, 51898, 52379, 52732, 53772, 54083, 54658, 56571);
  script_osvdb_id(78916, 80009, 80892, 80893, 82462, 82609, 83057, 84228, 87539);
  script_xref(name:"VMSA", value:"2012-0016");
  script_xref(name:"IAVA", value:"2012-A-0189");

  script_name(english:"VMSA-2012-0016 : VMware security updates for vSphere API and ESX Service Console");
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
"a. VMware vSphere API denial of service vulnerability

   The VMware vSphere API contains a denial of service
   vulnerability.  This issue allows an unauthenticated user to
   send a maliciously crafted API request and disable the host
   daemon. Exploitation of the issue would prevent management
   activities on the host but any virtual machines running on the
   host would be unaffected.

   VMware would like to thank Sebastian Tello of Core Security
   Technologies for reporting this issue to us.
 
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-5703 to this issue.

b. Update to ESX service console bind packages

   The ESX service console bind packages are updated to the
   following versions :

       bind-libs-9.3.6-20.P1.el5_8.2
       bind-utils-9.3.6-20.P1.el5_8.2

   These updates fix multiple security issues. The Common
   Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2012-1033, CVE-2012-1667, and
   CVE-2012-3817 to these issues.

c. Update to ESX service console python packages

   The ESX service console Python packages are updated to the
   following versions :

       python-2.4.3-46.el5_8.2.x86_64
       python-libs-2.4.3-46.el5_8.2.x86_64
  
   These updates fix multiple security issues. The Common
   Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2011-4940, CVE-2011-4944, and
   CVE-2012-1150 to these issues.

d. Update to ESX service console expat package

   The ESX service console expat package is updated to
   expat-1.95.8-11.el5_8.

   This update fixes multiple security issues. The Common
   Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2012-0876 and CVE-2012-1148 to these
   issues.

e. Update to ESX service console nspr and nss packages

   This patch updates the ESX service console Netscape Portable
   Runtime and Network Security Services RPMs to versions
   nspr-4.9.1.4.el5_8 and nss-3.13.5.4.9834, respectively, to
   resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-0441 to this issue. This patch
   also resolves a certificate trust issue caused by a fraudulent
   DigiNotar root certificate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000194.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2012-11-15");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201211401-SG",
    patch_updates : make_list("ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201211402-SG",
    patch_updates : make_list("ESX410-201301402-SG")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201211405-SG",
    patch_updates : make_list("ESX410-201307402-SG", "ESX410-201312403-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201211407-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201211401-SG",
    patch_updates : make_list("ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
