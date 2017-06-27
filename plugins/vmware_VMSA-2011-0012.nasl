#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0012. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(56508);
  script_version("$Revision: 1.47 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2010-0296", "CVE-2010-1083", "CVE-2010-1323", "CVE-2010-2492", "CVE-2010-2798", "CVE-2010-2938", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-3015", "CVE-2010-3066", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3086", "CVE-2010-3296", "CVE-2010-3432", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3699", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3865", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4161", "CVE-2010-4238", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4247", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4251", "CVE-2010-4255", "CVE-2010-4263", "CVE-2010-4343", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4655", "CVE-2011-0281", "CVE-2011-0282", "CVE-2011-0521", "CVE-2011-0536", "CVE-2011-0710", "CVE-2011-1010", "CVE-2011-1071", "CVE-2011-1090", "CVE-2011-1095", "CVE-2011-1478", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1658", "CVE-2011-1659");
  script_bugtraq_id(39042, 42124, 42237, 42477, 42527, 42529, 43022, 43221, 43353, 43480, 43578, 43787, 43806, 43809, 44219, 44301, 44354, 44549, 44630, 44648, 44665, 44754, 44755, 44758, 45004, 45014, 45028, 45029, 45037, 45039, 45054, 45058, 45063, 45064, 45073, 45099, 45118, 45208, 45262, 45323, 45661, 45795, 45972, 45986, 46265, 46271, 46421, 46492, 46563, 46637, 46766, 47056, 47185, 47370);
  script_osvdb_id(62387, 65078, 66751, 67327, 67366, 67881, 67893, 68169, 68170, 68171, 68172, 68173, 68174, 68177, 68266, 68303, 68305, 68631, 68721, 69013, 69117, 69162, 69190, 69424, 69469, 69521, 69522, 69527, 69530, 69531, 69551, 69552, 69553, 69577, 69578, 69610, 69613, 69653, 69701, 69788, 70226, 70228, 70264, 70290, 70375, 70378, 70379, 70380, 70477, 70483, 70659, 70660, 70665, 70908, 70909, 71599, 71601, 71604, 71660, 71972, 72796, 72996, 73041, 73047, 73048, 73407, 75261);
  script_xref(name:"VMSA", value:"2011-0012");
  script_xref(name:"IAVA", value:"2011-A-0147");

  script_name(english:"VMSA-2011-0012 : VMware ESXi and ESX updates to third-party libraries and ESX Service Console");
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
"a. ESX third-party update for Service Console kernel

   This update takes the console OS kernel package to
   kernel-2.6.18-238.9.1 which resolves multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2010-1083, CVE-2010-2492, CVE-2010-2798,
   CVE-2010-2938, CVE-2010-2942, CVE-2010-2943, CVE-2010-3015,
   CVE-2010-3066, CVE-2010-3067, CVE-2010-3078, CVE-2010-3086,
   CVE-2010-3296, CVE-2010-3432, CVE-2010-3442, CVE-2010-3477,
   CVE-2010-3699, CVE-2010-3858, CVE-2010-3859, CVE-2010-3865,
   CVE-2010-3876, CVE-2010-3877, CVE-2010-3880, CVE-2010-3904,
   CVE-2010-4072, CVE-2010-4073, CVE-2010-4075, CVE-2010-4080,
   CVE-2010-4081, CVE-2010-4083, CVE-2010-4157, CVE-2010-4158,
   CVE-2010-4161, CVE-2010-4238, CVE-2010-4242, CVE-2010-4243,
   CVE-2010-4247, CVE-2010-4248, CVE-2010-4249, CVE-2010-4251,
   CVE-2010-4255, CVE-2010-4263, CVE-2010-4343, CVE-2010-4346,
   CVE-2010-4526, CVE-2010-4655, CVE-2011-0521, CVE-2011-0710,
   CVE-2011-1010, CVE-2011-1090 and CVE-2011-1478 to these issues.

b. ESX third-party update for Service Console krb5 RPMs

   This patch updates the krb5-libs and krb5-workstation RPMs of the
   console OS to version 1.6.1-55.el5_6.1, which resolves multiple
   security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2010-1323, CVE-2011-0281, and CVE-2011-0282
   to these issues.

c. ESXi and ESX update to third-party component glibc

   The glibc third-party library is updated to resolve multiple
   security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2010-0296, CVE-2011-0536, CVE-2011-1071,
   CVE-2011-1095, CVE-2011-1658, and CVE-2011-1659 to these issues.

d. ESX update to third-party drivers mptsas, mpt2sas, and mptspi

   The mptsas, mpt2sas, and mptspi drivers are updated which addresses
   multiple security issues in the mpt2sas driver.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2011-1494 and CVE-2011-1495 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000164.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");
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


init_esx_check(date:"2011-10-12");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201203403-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110401-SG",
    patch_updates : make_list("ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110403-SG",
    patch_updates : make_list("ESX400-201203407-SG", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110409-SG",
    patch_updates : make_list("ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110201-SG",
    patch_updates : make_list("ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110224-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201203401-I-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201110401-SG",
    patch_updates : make_list("ESXi400-201203401-SG", "ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG", "ESXi400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201110201-SG",
    patch_updates : make_list("ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-0.3.515841")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
