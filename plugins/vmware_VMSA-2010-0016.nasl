#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0016. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(50611);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-4212", "CVE-2010-0291", "CVE-2010-0307", "CVE-2010-0415", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1321", "CVE-2010-1437");
  script_bugtraq_id(26070, 27006, 27703, 27706, 29502, 30494, 30496, 34257, 34408, 34409, 35193, 35196, 35263, 35416, 37749, 37906, 38027, 38144, 38165, 39044, 39569, 39719, 40235);
  script_osvdb_id(52963, 53383, 53384, 61795, 62045, 62168, 62379, 62380, 63630, 63631, 64549, 64744);
  script_xref(name:"VMSA", value:"2010-0016");

  script_name(english:"VMSA-2010-0016 : VMware ESXi and ESX third-party updates for Service Console and Likewise components");
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
"a. Service Console OS update for COS kernel

   This patch updates the service console kernel to fix multiple
   security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-0415, CVE-2010-0307,
   CVE-2010-0291, CVE-2010-0622, CVE-2010-1087, CVE-2010-1437, and
   CVE-2010-1088 to these issues.

b. Likewise package updates

   Updates to the likewisekrb5, likewiseopenldap, likewiseopen,
   and pamkrb5 packages address several security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-0844, CVE-2009-0845,
   CVE-2009-0846, CVE-2009-4212, and CVE-2010-1321 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000116.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 119, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2010-11-15");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201101401-SG",
    patch_updates : make_list("ESX400-201103401-SG", "ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010401-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201011402-SG", "ESX410-201101201-SG", "ESX410-201104401-SG", "ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010419-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201010401-SG",
    patch_updates : make_list("ESXi410-201101201-SG", "ESXi410-201104401-SG", "ESXi410-201110201-SG", "ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update01", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
