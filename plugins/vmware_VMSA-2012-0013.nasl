#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0013. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(61747);
  script_version("$Revision: 1.47 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2010-2761", "CVE-2010-4180", "CVE-2010-4252", "CVE-2010-4410", "CVE-2011-0014", "CVE-2011-1020", "CVE-2011-1089", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2699", "CVE-2011-3188", "CVE-2011-3209", "CVE-2011-3363", "CVE-2011-3597", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4110", "CVE-2011-4128", "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4325", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4609", "CVE-2011-4619", "CVE-2012-0050", "CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0207", "CVE-2012-0393", "CVE-2012-0815", "CVE-2012-0841", "CVE-2012-0864", "CVE-2012-1569", "CVE-2012-1573", "CVE-2012-1583", "CVE-2012-2110");
  script_bugtraq_id(40063, 44199, 45145, 45163, 45164, 46264, 46567, 46740, 47321, 48383, 48802, 49108, 49289, 49626, 49911, 50311, 50609, 50663, 50755, 50798, 50898, 51194, 51257, 51281, 51343, 51366, 51439, 51467, 51563, 52009, 52010, 52011, 52012, 52013, 52014, 52015, 52016, 52017, 52018, 52019, 52020, 52107, 52161, 52201, 52667, 52668, 52865, 53136, 53139, 53158, 53946, 53947, 53948, 53949, 53950, 53951, 53952, 53953, 53954, 53956, 53958, 53959, 53960);
  script_osvdb_id(65077, 69565, 69588, 69589, 69657, 70847, 71271, 73451, 74278, 74659, 74678, 74879, 74883, 75580, 75716, 75990, 76961, 77092, 77355, 77450, 77508, 77599, 77625, 78108, 78109, 78114, 78186, 78187, 78188, 78189, 78190, 78225, 78276, 78277, 78301, 78316, 78320, 79225, 79226, 79227, 79228, 79229, 79230, 79231, 79232, 79233, 79234, 79235, 79236, 79437, 80258, 80259, 80719, 80724, 81009, 81010, 81011, 81223, 81226, 81227, 81228, 81229, 81230, 81231, 81232, 81233, 81234, 81235, 81236, 81237, 81250, 81441, 82110, 82874, 82875, 82876, 82877, 82878, 82879, 82880, 82881, 82882, 82883, 82884, 82885, 82886);
  script_xref(name:"VMSA", value:"2012-0013");
  script_xref(name:"IAVA", value:"2012-A-0148");
  script_xref(name:"IAVA", value:"2012-A-0153");

  script_name(english:"VMSA-2012-0013 : VMware vSphere and vCOps updates to third-party libraries");
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
"a. vCenter and ESX update to JRE 1.6.0 Update 31

   The Oracle (Sun) JRE is updated to version 1.6.0_31, which
   addresses multiple security issues. Oracle has documented the
   CVE identifiers that are addressed by this update in the Oracle
   Java SE Critical Patch Update Advisory of February 2012.

b. vCenter Update Manager update to JRE 1.5.0 Update 36

   The Oracle (Sun) JRE is updated to 1.5.0_36 to address multiple
   security issues.  Oracle has documented the CVE identifiers that
   are addressed in JRE 1.5.0_36 in the Oracle Java SE Critical
   Patch Update Advisory for June 2012.

c. Update to ESX/ESXi userworld OpenSSL library

   The ESX/ESXi userworld OpenSSL library is updated from version
   0.9.8p to version 0.9.8t to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-4180, CVE-2010-4252,
   CVE-2011-0014, CVE-2011-4108, CVE-2011-4109, CVE-2011-4576,
   CVE-2011-4577, CVE-2011-4619, and CVE-2012-0050 to these issues.

d. Update to ESX service console OpenSSL RPM

   The service console OpenSSL RPM is updated to version
   0.9.8e-22.el5_8.3 to resolve a security issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-2110 to this issue.

e. Update to ESX service console kernel

   The ESX service console kernel is updated to resolve multiple
   security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2011-1833, CVE-2011-2484,
   CVE-2011-2496, CVE-2011-3188, CVE-2011-3209, CVE-2011-3363,
   CVE-2011-4110, CVE-2011-1020, CVE-2011-4132, CVE-2011-4324,
   CVE-2011-4325, CVE-2012-0207, CVE-2011-2699, and CVE-2012-1583
   to these issues.

f. Update to ESX service console Perl RPM

   The ESX service console Perl RPM is updated to
   perl-5.8.8.32.1.8999.vmw to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-2761, CVE-2010-4410, and
   CVE-2011-3597 to these issues.

g. Update to ESX service console libxml2 RPMs

   The ESX service console libmxl2 RPMs are updated to
   libxml2-2.6.26-2.1.15.el5_8.2 and
   libxml2-python-2.6.26-2.1.15.el5_8.2 to resolve a security
   issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-0841 to this issue.

h. Update to ESX service console glibc RPM

   The ESX service console glibc RPM is updated to version
   glibc-2.5-81.el5_8.1 to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2009-5029, CVE-2009-5064,
   CVE-2010-0830, CVE-2011-1089, CVE-2011-4609, and CVE-2012-0864
   to these issue.

i. Update to ESX service console GnuTLS RPM

   The ESX service console GnuTLS RPM is updated to version
   1.4.1-7.el5_8.2 to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2011-4128, CVE-2012-1569, and
   CVE-2012-1573 to these issues.

j. Update to ESX service console popt, rpm, rpm-libs,
   and rpm-python RPMS

   The ESX service console popt, rpm, rpm-libs, and rpm-python RPMS
   are updated to the following versions to resolve multiple
   security issues :
      - popt-1.10.2.3-28.el5_8
      - rpm-4.4.2.3-28.el5_8
      - rpm-libs-4.4.2.3-28.el5_8
      - rpm-python-4.4.2.3-28.el5_8

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-0060, CVE-2012-0061, and
   CVE-2012-0815 to these issues.

k. Vulnerability in third-party Apache Struts component

   The version of Apache Struts in vCenter Operations has been
   updated to 2.3.4 which addresses an arbitrary file overwrite
   vulnerability. This vulnerability allows an attacker to create
   a denial of service by overwriting arbitrary files without
   authentication. The attacker would need to be on the same network
   as the system where vCOps is installed.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2012-0393 to this issue.

   Note: Apache struts 2.3.4 addresses the following issues as well :
   CVE-2011-5057, CVE-2012-0391, CVE-2012-0392, CVE-2012-0394. It
   was found that these do not affect vCOps.

   VMware would like to thank Alexander Minozhenko from ERPScan for
   reporting this issue to us."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000197.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts ExceptionDelegator < 2.3.1.1 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/31");
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


init_esx_check(date:"2012-08-30");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201209401-SG",
    patch_updates : make_list("ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201209402-SG",
    patch_updates : make_list("ESX400-201305404-SG", "ESX400-201310402-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201209404-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208101-SG",
    patch_updates : make_list("ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208102-SG",
    patch_updates : make_list("ESX410-201301405-SG", "ESX410-201304402-SG", "ESX410-201307405-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208103-SG",
    patch_updates : make_list("ESX410-201307403-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208104-SG",
    patch_updates : make_list("ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208105-SG",
    patch_updates : make_list("ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208106-SG",
    patch_updates : make_list("ESX410-201307404-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208107-SG",
    patch_updates : make_list("ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201208101-SG",
    patch_updates : make_list("ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-1.25.912577")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
