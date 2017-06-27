#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0004. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(52582);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2005-4889", "CVE-2010-2059", "CVE-2010-2199", "CVE-2010-3316", "CVE-2010-3435", "CVE-2010-3609", "CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3762", "CVE-2010-3853");
  script_bugtraq_id(40512, 42472, 43487, 44590, 45133, 45137, 45385, 46772);
  script_osvdb_id(65143, 65144, 68271, 68992, 68993, 68994, 69558, 69559, 71019);
  script_xref(name:"VMSA", value:"2011-0004");
  script_xref(name:"IAVA", value:"2011-A-0066");

  script_name(english:"VMSA-2011-0004 : VMware ESX/ESXi SLPD denial of service vulnerability and ESX third-party updates for Service Console packages bind, pam, and rpm.");
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
"a. Service Location Protocol daemon DoS

   This patch fixes a denial-of-service vulnerability in
   the Service Location Protocol daemon (SLPD). Exploitation of this
   vulnerability could cause SLPD to consume significant CPU
   resources.

   VMware would like to thank Nicolas Gregoire and US CERT for
   reporting this issue to us.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-3609 to this issue.

b. Service Console update for bind

   This patch updates the bind-libs and bind-utils RPMs to version
   9.3.6-4.P1.el5_5.3, which resolves multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-3613, CVE-2010-3614, and
   CVE-2010-3762 to these issues.

c. Service Console update for pam

   This patch updates the pam RPM to pam_0.99.6.2-3.27.5437.vmw,
   which resolves multiple security issues with PAM modules.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-3316, CVE-2010-3435, and
   CVE-2010-3853 to these issues.

d. Service Console update for rpm, rpm-libs, rpm-python, and popt

   This patch updates rpm, rpm-libs, and rpm-python RPMs to
   4.4.2.3-20.el5_5.1, and popt to version 1.10.2.3-20.el5_5.1,
   which resolves a security issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-2059 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000159.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/08");
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


init_esx_check(date:"2011-03-07");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103401-SG",
    patch_updates : make_list("ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103404-SG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103406-SG",
    patch_updates : make_list("ESX400-201203405-SG", "ESX400-201209404-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103407-SG",
    patch_updates : make_list("ESX400-201305403-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201101201-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201104401-SG", "ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201104407-SG",
    patch_updates : make_list("ESX410-201211402-SG", "ESX410-201301402-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110207-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201103401-SG",
    patch_updates : make_list("ESXi400-201104401-SG", "ESXi400-201110401-SG", "ESXi400-201203401-SG", "ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG", "ESXi400-Update03", "ESXi400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201101201-SG",
    patch_updates : make_list("ESXi410-201104401-SG", "ESXi410-201110201-SG", "ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update01", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
