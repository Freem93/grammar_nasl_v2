#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0002. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(45386);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2716", "CVE-2009-2718", "CVE-2009-2719", "CVE-2009-2720", "CVE-2009-2721", "CVE-2009-2722", "CVE-2009-2723", "CVE-2009-2724", "CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3864", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3885", "CVE-2009-3886");
  script_bugtraq_id(34240, 35922, 35939, 35943, 35944, 35946, 35958, 36881);
  script_osvdb_id(53164, 53165, 53166, 53167, 53168, 53169, 53170, 53171, 53172, 53173, 53174, 53175, 53176, 53177, 53178, 56783, 56784, 56785, 56786, 56788, 56955, 56956, 56957, 56958, 56959, 56961, 56962, 56964, 56984, 57431, 59705, 59706, 59707, 59708, 59709, 59710, 59711, 59712, 59713, 59714, 59716, 59717, 59718, 59915, 59916, 59917, 59918, 59919, 59920, 59921, 59922, 59923, 59924);
  script_xref(name:"VMSA", value:"2010-0002");

  script_name(english:"VMSA-2010-0002 : VMware vCenter update release addresses multiple security issues in Java JRE");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Java JRE Security Update

  JRE update to version 1.5.0_22, which addresses multiple security
  issues that existed in earlier releases of JRE.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  JRE 1.5.0_18: CVE-2009-1093, CVE-2009-1094, CVE-2009-1095,
  CVE-2009-1096, CVE-2009-1097, CVE-2009-1098, CVE-2009-1099,
  CVE-2009-1100, CVE-2009-1101, CVE-2009-1102, CVE-2009-1103,
  CVE-2009-1104, CVE-2009-1105, CVE-2009-1106, and CVE-2009-1107.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  JRE 1.5.0_20: CVE-2009-2625, CVE-2009-2670, CVE-2009-2671,
  CVE-2009-2672, CVE-2009-2673, CVE-2009-2675, CVE-2009-2676,
  CVE-2009-2716, CVE-2009-2718, CVE-2009-2719, CVE-2009-2720,
  CVE-2009-2721, CVE-2009-2722, CVE-2009-2723, CVE-2009-2724.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  JRE 1.5.0_22: CVE-2009-3728, CVE-2009-3729, CVE-2009-3864,
  CVE-2009-3865, CVE-2009-3866, CVE-2009-3867, CVE-2009-3868,
  CVE-2009-3869, CVE-2009-3871, CVE-2009-3872, CVE-2009-3873,
  CVE-2009-3874, CVE-2009-3875, CVE-2009-3876, CVE-2009-3877,
  CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882,
  CVE-2009-3883, CVE-2009-3884, CVE-2009-3886, CVE-2009-3885."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000097.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 22, 94, 119, 189, 200, 264, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/31");
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


init_esx_check(date:"2010-01-29");
flag = 0;


if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-201003403-SG",
    patch_updates : make_list("ESX350-201203401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201005402-SG",
    patch_updates : make_list("ESX400-201103403-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
